package mapping

// Paginated delivery of oversized map / confirmSpend payloads.
//
// A caller (relay bot) splits its JSON-encoded VerificationRequest payload into
// N <= MaxPagesPerParent pages, each under the VSC L2 transaction cap
// (`MAX_TX_SIZE = 16384` bytes). The contract accepts pages in any order.
// Duplicate pages are idempotent no-ops (bitmap dedupe).
// When the last outstanding page arrives, pages are reassembled, verified
// against a content hash encoded in `parent_id`, and the regular
// HandleMap/HandleConfirmSpend path is invoked.
//
// This mirrors the Lean model in magi-lean `MagiLean.Security.MappingBot`:
//   - `PagePlanFitsL2` / `pagination_plan_each_page_fits_l2`     (MaxPageBytes bound)
//   - `contractSubmit_idempotent` / `contractSubmit_monotone`    (bitmap-based dedupe)
//   - `pagination_reconstructs_original`                          (content-hash verified assembly)

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// PagePayloadKind disambiguates map vs confirmSpend pagination channels.
type PagePayloadKind uint8

const (
	PagePayloadMap          PagePayloadKind = 1
	PagePayloadConfirmSpend PagePayloadKind = 2
)

// MaxPagesPerParent caps the meta bitmap so that state cannot be expanded
// without bound by a malicious submitter. 128 pages * 16 KB/page = 2 MB
// maximum reassembled payload, which is far beyond any realistic BTC tx
// + Merkle proof combination.
const MaxPagesPerParent uint32 = 128

// MaxPageBytes mirrors the Lean-proven L2 submission cap (`l2MaxTxSize`).
// Individual pages carrying more bytes than this are rejected because they
// could never have been delivered through a single L2 transaction.
const MaxPageBytes = 16384

// State-key prefixes.
//
// pg-<kind>-<parentId>-<idx>  -> raw page payload bytes
// pgm-<kind>-<parentId>       -> meta (kind, total, recv, bitmap)
// pgo-<kind>-<parentId>       -> 1-byte marker set after successful assembly,
//                                so duplicate full-payload replay is a no-op
const (
	pageDataPrefix = "pg" + constants.DirPathDelimiter
	pageMetaPrefix = "pgm" + constants.DirPathDelimiter
	pageDonePrefix = "pgo" + constants.DirPathDelimiter
)

// PageStore is the minimal KV surface used by the pagination layer. In
// production this is backed by the contract state DB via `sdk.State*`; in
// unit tests it is backed by an in-memory map for deterministic coverage.
type PageStore interface {
	Get(key string) string
	Set(key, value string)
	Delete(key string)
}

// SdkPageStore binds PageStore to the live contract state DB.
type SdkPageStore struct{}

func (SdkPageStore) Get(key string) string {
	p := sdk.StateGetObject(key)
	if p == nil {
		return ""
	}
	return *p
}

func (SdkPageStore) Set(key, value string) { sdk.StateSetObject(key, value) }

func (SdkPageStore) Delete(key string) { sdk.StateDeleteObject(key) }

// InMemoryPageStore is an ephemeral PageStore useful for unit tests and for
// any future off-chain simulation of the pagination protocol.
type InMemoryPageStore struct {
	Data map[string]string
}

func NewInMemoryPageStore() *InMemoryPageStore {
	return &InMemoryPageStore{Data: make(map[string]string)}
}

func (s *InMemoryPageStore) Get(key string) string { return s.Data[key] }

func (s *InMemoryPageStore) Set(key, value string) { s.Data[key] = value }

func (s *InMemoryPageStore) Delete(key string) { delete(s.Data, key) }

// pageMeta is an on-wire-stable compact record of pagination progress for
// a single parentId. Kept binary to minimise contract-state bytes.
type pageMeta struct {
	Kind   PagePayloadKind
	Total  uint32
	Recv   uint32
	Bitmap []byte
}

func (m *pageMeta) isComplete() bool { return m.Recv == m.Total }

func (m *pageMeta) hasPage(idx uint32) bool {
	byteIdx := idx / 8
	bitMask := byte(1) << (idx % 8)
	if int(byteIdx) >= len(m.Bitmap) {
		return false
	}
	return m.Bitmap[byteIdx]&bitMask != 0
}

func (m *pageMeta) setPage(idx uint32) {
	byteIdx := idx / 8
	bitMask := byte(1) << (idx % 8)
	m.Bitmap[byteIdx] |= bitMask
}

func encodeMeta(m *pageMeta) []byte {
	out := make([]byte, 1+4+4+len(m.Bitmap))
	out[0] = byte(m.Kind)
	binary.LittleEndian.PutUint32(out[1:5], m.Total)
	binary.LittleEndian.PutUint32(out[5:9], m.Recv)
	copy(out[9:], m.Bitmap)
	return out
}

func decodeMeta(raw []byte) (*pageMeta, error) {
	if len(raw) < 9 {
		return nil, ce.NewContractError(ce.ErrInput, "page meta too short")
	}
	m := &pageMeta{
		Kind:   PagePayloadKind(raw[0]),
		Total:  binary.LittleEndian.Uint32(raw[1:5]),
		Recv:   binary.LittleEndian.Uint32(raw[5:9]),
		Bitmap: append([]byte(nil), raw[9:]...),
	}
	want := (m.Total + 7) / 8
	if uint32(len(m.Bitmap)) != want {
		return nil, ce.NewContractError(ce.ErrInput, "page meta bitmap size mismatch")
	}
	if m.Recv > m.Total {
		return nil, ce.NewContractError(ce.ErrInput, "page meta recv > total")
	}
	return m, nil
}

func pageDataKey(kind PagePayloadKind, parentId string, idx uint32) string {
	return pageDataPrefix +
		strconv.FormatUint(uint64(kind), 10) + constants.DirPathDelimiter +
		parentId + constants.DirPathDelimiter +
		strconv.FormatUint(uint64(idx), 10)
}

func pageMetaKey(kind PagePayloadKind, parentId string) string {
	return pageMetaPrefix +
		strconv.FormatUint(uint64(kind), 10) + constants.DirPathDelimiter +
		parentId
}

func pageDoneKey(kind PagePayloadKind, parentId string) string {
	return pageDonePrefix +
		strconv.FormatUint(uint64(kind), 10) + constants.DirPathDelimiter +
		parentId
}

// ComputeParentId derives the canonical content-addressed parent id for a
// full pre-pagination payload. Clients (the mapping bot) must compute the id
// over the DECODED JSON payload bytes (pre-base64) before splitting into
// pages so the contract can verify on reassembly that no bytes were tampered
// with. See the wire-format comment on `SubmitPage` for the relationship
// between page bytes and the parent-id digest domain.
func ComputeParentId(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// SubmitPageResult reports what happened during a page commit.
type SubmitPageResult struct {
	// FreshlyAccepted is true iff this call recorded a new page. A duplicate
	// submission of a previously-recorded page returns false (idempotent
	// no-op), matching Lean's `contractSubmit_idempotent`.
	FreshlyAccepted bool
	// Complete is true iff after this call every page has been received.
	Complete bool
	// Assembled is non-nil iff Complete was transitioned on this call. In
	// that case it holds the full reassembled payload, ready for dispatch.
	// The pagination bookkeeping keys for this parentId have been cleaned up.
	Assembled []byte
}

// SubmitPage records a single page of a pagination plan. If the submission
// completes the plan, the assembled payload is returned and state is cleaned
// up atomically from the caller's perspective.
//
// Wire format: `data` is a base64 (URL, no padding) substring of the full
// base64-encoded JSON payload. Pages are concatenated in index order to
// reconstruct the full base64 string, which is then decoded to recover the
// original JSON bytes. The `parent_id` is the sha256 digest of the decoded
// JSON bytes (not the base64 representation), so the hash domain matches
// what the bot computes over its pre-encoding payload.
//
// Rationale for base64 on the wire: raw bytes embedded in the JSON `payload`
// string field can explode up to 6x due to `\uXXXX` escape sequences for
// non-ASCII bytes, pushing pages past the L2 MAX_TX_SIZE cap even when the
// raw chunk is well under it. Base64 (URL-alphabet, no padding) is ASCII-
// only and has a predictable 4/3 expansion ratio, guaranteeing per-page
// budget accounting matches the Lean `PagePlanFitsL2` predicate.
func SubmitPage(
	store PageStore,
	kind PagePayloadKind,
	parentId string,
	pageIdx, totalPages uint32,
	data []byte,
) (*SubmitPageResult, error) {
	if len(parentId) == 0 {
		return nil, ce.NewContractError(ce.ErrInput, "parent_id required")
	}
	if totalPages == 0 {
		return nil, ce.NewContractError(ce.ErrInput, "total_pages must be > 0")
	}
	if totalPages > MaxPagesPerParent {
		return nil, ce.NewContractError(ce.ErrInput, "total_pages exceeds MaxPagesPerParent")
	}
	if pageIdx >= totalPages {
		return nil, ce.NewContractError(ce.ErrInput, "page_idx out of range")
	}
	if len(data) > MaxPageBytes {
		return nil, ce.NewContractError(ce.ErrInput, "page data exceeds MaxPageBytes")
	}

	// If the full payload was already assembled previously, treat any further
	// submissions against the same parentId as idempotent no-ops. This
	// mirrors the Lean `contractSubmit_operator_independent` guarantee for
	// the whole-job replay case.
	if store.Get(pageDoneKey(kind, parentId)) != "" {
		return &SubmitPageResult{FreshlyAccepted: false, Complete: true}, nil
	}

	metaKey := pageMetaKey(kind, parentId)
	metaRaw := store.Get(metaKey)

	var meta *pageMeta
	if metaRaw == "" {
		bitmapLen := (totalPages + 7) / 8
		meta = &pageMeta{
			Kind:   kind,
			Total:  totalPages,
			Recv:   0,
			Bitmap: make([]byte, bitmapLen),
		}
	} else {
		var err error
		meta, err = decodeMeta([]byte(metaRaw))
		if err != nil {
			return nil, err
		}
		// meta.Kind equality is guaranteed by the key namespace (see
		// pageMetaKey). We still persist it for forensic traceability and
		// consistency with on-wire bindings, but there is no runtime check
		// needed here.
		if meta.Total != totalPages {
			return nil, ce.NewContractError(ce.ErrInput, "total_pages mismatch for existing parent_id")
		}
	}

	if meta.hasPage(pageIdx) {
		// Duplicate page: no-op, but report current completeness.
		return &SubmitPageResult{FreshlyAccepted: false, Complete: meta.isComplete()}, nil
	}

	store.Set(pageDataKey(kind, parentId, pageIdx), string(data))
	meta.setPage(pageIdx)
	meta.Recv++
	store.Set(metaKey, string(encodeMeta(meta)))

	if !meta.isComplete() {
		return &SubmitPageResult{FreshlyAccepted: true, Complete: false}, nil
	}

	// Assemble + verify + cleanup.
	assembled, err := assembleAndVerify(store, kind, parentId, meta)
	if err != nil {
		return nil, err
	}
	store.Set(pageDoneKey(kind, parentId), "1")
	return &SubmitPageResult{FreshlyAccepted: true, Complete: true, Assembled: assembled}, nil
}

func assembleAndVerify(
	store PageStore,
	kind PagePayloadKind,
	parentId string,
	meta *pageMeta,
) ([]byte, error) {
	total := meta.Total
	// Pre-compute total size to avoid repeated allocations.
	var size int
	parts := make([][]byte, total)
	for i := uint32(0); i < total; i++ {
		key := pageDataKey(kind, parentId, i)
		chunk := store.Get(key)
		if chunk == "" {
			return nil, ce.NewContractError(ce.ErrInput, "missing page data during assembly")
		}
		parts[i] = []byte(chunk)
		size += len(parts[i])
	}

	encoded := make([]byte, 0, size)
	for i := uint32(0); i < total; i++ {
		encoded = append(encoded, parts[i]...)
	}

	// Pages carry base64 (URL alphabet, no padding) substrings of the full
	// encoded payload; decode before hashing so the parent-id domain matches
	// the original JSON bytes the bot committed to. See SubmitPage wire-
	// format note.
	out, err := base64.RawURLEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, ce.NewContractError(ce.ErrInput, "page payload base64 decode failed")
	}

	if ComputeParentId(out) != parentId {
		return nil, ce.NewContractError(ce.ErrInput, "parent_id content-hash mismatch")
	}

	// Cleanup pagination keys. The done-marker is written by the caller so
	// future replays short-circuit without re-verifying. Callers MUST finish
	// dispatch before considering the pagination complete; if dispatch itself
	// aborts, the whole tx reverts and these deletions are rolled back.
	for i := uint32(0); i < total; i++ {
		store.Delete(pageDataKey(kind, parentId, i))
	}
	store.Delete(pageMetaKey(kind, parentId))

	return out, nil
}

// PageInspector is exported solely for tests. It reports the current meta
// state of a pagination plan without mutating storage.
type PageInspector struct{ Store PageStore }

func (p PageInspector) Meta(kind PagePayloadKind, parentId string) (total, recv uint32, complete, done bool) {
	if p.Store.Get(pageDoneKey(kind, parentId)) != "" {
		done = true
	}
	raw := p.Store.Get(pageMetaKey(kind, parentId))
	if raw == "" {
		return 0, 0, false, done
	}
	m, err := decodeMeta([]byte(raw))
	if err != nil {
		return 0, 0, false, done
	}
	return m.Total, m.Recv, m.isComplete(), done
}
