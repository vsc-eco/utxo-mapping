package mapping

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"testing"

	"btc-mapping-contract/contract/constants"
)

type InMemoryPageStore struct {
	Data   map[string]string
	Writes int
}

func NewInMemoryPageStore() *InMemoryPageStore {
	return &InMemoryPageStore{Data: make(map[string]string)}
}

func (s *InMemoryPageStore) Get(key string) string { return s.Data[key] }

func (s *InMemoryPageStore) Set(key, value string) {
	s.Data[key] = value
	s.Writes++
}

func (s *InMemoryPageStore) Delete(key string) {
	delete(s.Data, key)
	s.Writes++
}

type PageInspector struct{ Store PageStore }

func (p PageInspector) Meta(kind PagePayloadKind, sender string, txid [32]byte) (total uint32, recv uint32, exists bool) {
	raw := p.Store.Get(keyPageMeta(kind, sender, txid))
	if raw == "" {
		return 0, 0, false
	}
	meta, err := decodeMeta([]byte(raw))
	if err != nil {
		return 0, 0, false
	}
	return uint32(meta.Total), meta.recvCount(), true
}

func encodeForWire(raw []byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(raw))
}

func splitPages(payload []byte, pageSize int) []string {
	if pageSize <= 0 {
		pageSize = 8192
	}
	wire := encodeForWire(payload)
	if len(wire) == 0 {
		return []string{""}
	}
	var pages []string
	for i := 0; i < len(wire); i += pageSize {
		end := i + pageSize
		if end > len(wire) {
			end = len(wire)
		}
		pages = append(pages, string(wire[i:end]))
	}
	return pages
}

func mustTxid(fill byte) [32]byte {
	var txid [32]byte
	for i := range txid {
		txid[i] = fill
	}
	return txid
}

func withRetentionWindow(t *testing.T, store *InMemoryPageStore, lastHeight uint32) {
	t.Helper()
	store.Set(constants.LastHeightKey, strconv.FormatUint(uint64(lastHeight), 10))
}

func putObserved(t *testing.T, store *InMemoryPageStore, blockHeight uint32, txid [32]byte, vout uint32) {
	t.Helper()
	entry, err := makeObservedEntry(hex.EncodeToString(txid[:]), vout)
	if err != nil {
		t.Fatalf("makeObservedEntry: %v", err)
	}
	buf := make([]byte, observedEntrySize)
	copy(buf, entry[:])
	store.Set(observedBlockKey(blockHeight), string(buf))
}

func TestSubmitPage_SinglePage_CompletesImmediately(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	store.Writes = 0
	payload := []byte(`{"tx_data":{"raw_tx_hex":"deadbeef"}}`)
	assembled, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:1", mustTxid(0x11), 0, 5000, 0, 1, encodeForWire(payload))
	if err != nil {
		t.Fatalf("SubmitPage: %v", err)
	}
	if !bytes.Equal(assembled, payload) {
		t.Fatalf("assembled mismatch: got %q, want %q", assembled, payload)
	}
	if store.Writes != 0 {
		t.Fatalf("expected zero writes, got %d", store.Writes)
	}
}

func TestSubmitPage_MultiPage_InOrder_AssemblesExact(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	payload := bytes.Repeat([]byte("ABCDEFGH"), 5000)
	pages := splitPages(payload, 9000)
	if len(pages) < 3 {
		t.Fatalf("expected >= 3 pages, got %d", len(pages))
	}

	var assembled []byte
	var err error
	for i, p := range pages {
		assembled, err = SubmitPage(store, PagePayloadMap, "did:vsc:relay:2", mustTxid(0x22), 1, 5000, uint32(i), uint32(len(pages)), []byte(p))
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		if i < len(pages)-1 && assembled != nil {
			t.Fatalf("page %d: premature assembly", i)
		}
	}
	if !bytes.Equal(assembled, payload) {
		t.Fatalf("assembled mismatch: got %d want %d", len(assembled), len(payload))
	}
}

func TestSubmitPage_MultiPage_OutOfOrder_AssemblesExact(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	payload := bytes.Repeat([]byte("xy"), 20_000)
	pages := splitPages(payload, 8_000)
	total := uint32(len(pages))
	if total < 3 {
		t.Fatalf("expected >= 3 pages for out-of-order test, got %d", total)
	}

	// Deterministic permutation derived from a linear-congruential walk so
	// that every page index is visited exactly once, even as the number of
	// base64-wire pages varies with encoding overhead.
	order := make([]int, total)
	for i := range order {
		order[i] = int((uint32(i)*7 + 3) % total)
	}
	seen := make(map[int]bool, total)
	for _, idx := range order {
		seen[idx] = true
	}
	if len(seen) != int(total) {
		// Fall back to a trivial reverse permutation if the LCG collides.
		for i := range order {
			order[i] = int(total) - 1 - i
		}
	}

	var assembled []byte
	for _, i := range order {
		result, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:3", mustTxid(0x33), 2, 5000, uint32(i), total, []byte(pages[i]))
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		if result != nil {
			assembled = result
		}
	}

	if !bytes.Equal(assembled, payload) {
		t.Fatalf("out-of-order assembly mismatch (got %d bytes, want %d)", len(assembled), len(payload))
	}
}

func TestSubmitPage_DuplicatePage_IsNoop(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	payload := bytes.Repeat([]byte("Q"), 10_000)
	pages := splitPages(payload, 4_000)

	_, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:4", mustTxid(0x44), 1, 5000, 0, uint32(len(pages)), []byte(pages[0]))
	if err != nil {
		t.Fatal(err)
	}

	snapshot := make(map[string]string, len(store.Data))
	for k, v := range store.Data {
		snapshot[k] = v
	}
	writes := store.Writes

	out, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:4", mustTxid(0x44), 1, 5000, 0, uint32(len(pages)), []byte(pages[0]))
	if err != nil {
		t.Fatalf("duplicate: %v", err)
	}
	if out != nil {
		t.Fatal("duplicate should not assemble")
	}
	if store.Writes != writes {
		t.Fatalf("duplicate changed writes %d -> %d", writes, store.Writes)
	}
	if len(store.Data) != len(snapshot) {
		t.Fatalf("duplicate submission mutated store (len %d -> %d)", len(snapshot), len(store.Data))
	}
	for k, v := range snapshot {
		if store.Data[k] != v {
			t.Fatalf("duplicate submission mutated key %s", k)
		}
	}
}

func TestSubmitPage_MidStreamMismatch_Rejects(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	payload := bytes.Repeat([]byte("legit"), 5_000)
	pages := splitPages(payload, 4_000)
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:5", mustTxid(0x55), 2, 5000, 0, uint32(len(pages)), []byte(pages[0])); err != nil {
		t.Fatal(err)
	}
	_, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:5", mustTxid(0x55), 2, 5000, 1, uint32(len(pages))+1, []byte(pages[1]))
	if err == nil {
		t.Fatal("expected mid-stream mismatch error")
	}
}

func TestSubmitPage_Page0Mismatch_AutoRestarts(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	txid := mustTxid(0x56)
	sender := "did:vsc:relay:6"
	payload := bytes.Repeat([]byte("r"), 10_000)
	wire := encodeForWire(payload)
	if _, err := SubmitPage(store, PagePayloadMap, sender, txid, 0, 5000, 0, 3, wire[:2000]); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitPage(store, PagePayloadMap, sender, txid, 0, 5000, 0, 4, wire[:2000]); err != nil {
		t.Fatalf("expected auto restart, got %v", err)
	}
	insp := PageInspector{Store: store}
	total, recv, exists := insp.Meta(PagePayloadMap, sender, txid)
	if !exists || total != 4 || recv != 1 {
		t.Fatalf("unexpected meta after restart: exists=%v total=%d recv=%d", exists, total, recv)
	}
}

func TestSubmitPage_KindsAreIndependent(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	payload := []byte("hello")
	wire := encodeForWire(payload)
	txid := mustTxid(0x60)

	r1, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:7", txid, 0, 5000, 0, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r1, payload) {
		t.Fatal("expected map assembly")
	}

	r2, err := SubmitPage(store, PagePayloadConfirmSpend, "did:vsc:relay:7", txid, 0, 5000, 0, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r2, payload) {
		t.Fatal("confirmSpend channel assembled mismatch")
	}
}

func TestSubmitPage_PageIdxOutOfRange_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:8", mustTxid(0x70), 0, 5000, 5, 3, []byte("AAAA")); err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestSubmitPage_ZeroTotalPages_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:9", mustTxid(0x71), 0, 5000, 0, 0, nil); err == nil {
		t.Fatal("expected zero-total error")
	}
}

func TestSubmitPage_ExceedMaxPagesPerPlan_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:10", mustTxid(0x72), 0, 5000, 0, constants.MaxPagesPerPlan+1, nil); err == nil {
		t.Fatal("expected total-pages cap error")
	}
}

func TestSubmitPage_OversizePageBytes_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	oversizeRaw := bytes.Repeat([]byte{'a'}, constants.MaxRawPageBytes+1)
	oversize := encodeForWire(oversizeRaw)
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:11", mustTxid(0x73), 0, 5000, 0, 1, oversize); err == nil {
		t.Fatal("expected oversize-page error")
	}
}

func TestSubmitPage_PostCompletionReplay_StartsFreshPlan(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	payload := bytes.Repeat([]byte("complete-me"), 800)
	pages := splitPages(payload, 5000)
	txid := mustTxid(0x74)
	sender := "did:vsc:relay:12"
	for i := range pages {
		if _, err := SubmitPage(store, PagePayloadMap, sender, txid, 0, 5000, uint32(i), uint32(len(pages)), []byte(pages[i])); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SubmitPage(store, PagePayloadMap, sender, txid, 0, 5000, 0, 2, []byte("QUFB")); err != nil {
		t.Fatal(err)
	}
	insp := PageInspector{Store: store}
	total, recv, exists := insp.Meta(PagePayloadMap, sender, txid)
	if !exists || total != 2 || recv != 1 {
		t.Fatalf("expected fresh plan state, got exists=%v total=%d recv=%d", exists, total, recv)
	}
}

func TestSubmitPage_MonotoneBitmap(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	payload := bytes.Repeat([]byte("M"), 30_000)
	pages := splitPages(payload, 5_000)
	total := uint32(len(pages))
	txid := mustTxid(0x75)
	sender := "did:vsc:relay:13"

	insp := PageInspector{Store: store}
	prevRecv := uint32(0)
	for i, p := range pages {
		if _, err := SubmitPage(store, PagePayloadMap, sender, txid, 0, 5000, uint32(i), total, []byte(p)); err != nil {
			t.Fatal(err)
		}
		if i == len(pages)-1 {
			_, _, exists := insp.Meta(PagePayloadMap, sender, txid)
			if exists {
				t.Fatal("expected meta cleared after completion")
			}
			continue
		}
		_, recv, exists := insp.Meta(PagePayloadMap, sender, txid)
		if !exists {
			t.Fatal("meta unexpectedly missing")
		}
		if recv <= prevRecv {
			t.Fatalf("Recv did not increase on fresh page %d (%d -> %d)", i, prevRecv, recv)
		}
		prevRecv = recv
	}
}

func TestSubmitPage_DifferentSenders_DoNotCollide(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	txid := mustTxid(0x80)
	payloadA := splitPages(bytes.Repeat([]byte("A"), 9000), 4000)

	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:a", txid, 0, 5000, 0, uint32(len(payloadA)), []byte(payloadA[0])); err != nil {
		t.Fatal(err)
	}
	assembledB, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:b", txid, 0, 5000, 0, 1, encodeForWire([]byte("independent")))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(assembledB, []byte("independent")) {
		t.Fatal("sender B should complete independently")
	}
}

func TestSubmitPage_ObservedPreCheck_RejectsLoserRace(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	txid := mustTxid(0x81)
	putObserved(t, store, 5000, txid, 3)
	writes := store.Writes
	_, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:obs", txid, 3, 5000, 0, 2, []byte("QUFB"))
	if err == nil {
		t.Fatal("expected observed pre-check rejection")
	}
	if store.Writes != writes {
		t.Fatalf("expected zero writes after observed rejection, got %d -> %d", writes, store.Writes)
	}
}

func TestSubmitPage_HeightOutOfRetention_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 2000)
	min := retainFrom(2000)
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:h", mustTxid(0x82), 0, min-1, 0, 1, []byte("QUFB")); err == nil {
		t.Fatal("expected pruned-height rejection")
	}
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:h", mustTxid(0x82), 0, 2001, 0, 1, []byte("QUFB")); err == nil {
		t.Fatal("expected future-height rejection")
	}
}

func TestSubmitPage_MaxPlansPerHeight_Enforced(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	height := uint32(5000)
	for i := uint32(0); i < constants.MaxPlansPerHeight; i++ {
		txid := mustTxid(byte(i))
		if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:cap"+strconv.FormatUint(uint64(i), 10), txid, 0, height, 0, 2, []byte("QUFB")); err != nil {
			t.Fatalf("seed plan %d: %v", i, err)
		}
	}
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:overflow", mustTxid(0x90), 0, height, 0, 2, []byte("QUFB")); err == nil {
		t.Fatal("expected max plans per height error")
	}
}

func TestSubmitPage_Base64Alignment_EnforcedOnNonFinalPages(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:align", mustTxid(0x91), 0, 5000, 0, 2, []byte("QUF")); err == nil {
		t.Fatal("expected non-final alignment rejection")
	}
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:align", mustTxid(0x91), 0, 5000, 1, 2, []byte("QUF")); err != nil {
		t.Fatalf("expected final page to allow non-4 alignment, got %v", err)
	}
}

func TestPrunePagesForHeight_ClearsAllPlans(t *testing.T) {
	store := NewInMemoryPageStore()
	height := uint32(111)
	txid := mustTxid(0x92)
	sender := "did:vsc:relay:prune"
	meta := &pageMeta{TargetHeight: height, Total: 3, Bitmap: []byte{0b00000111}}
	store.Set(keyPageMeta(PagePayloadMap, sender, txid), string(encodeMeta(meta)))
	store.Set(keyPageData(PagePayloadMap, sender, txid, 0), "a")
	store.Set(keyPageData(PagePayloadMap, sender, txid, 1), "b")
	store.Set(keyPageData(PagePayloadMap, sender, txid, 2), "c")
	iv, _ := encodePageIndexValue(PagePayloadMap, sender, txid)
	store.Set(keyPageIndex(height, 0), string(iv))
	writePageCount(store, height, 1)

	prunePagesForHeightStore(store, height)

	if store.Get(keyPageMeta(PagePayloadMap, sender, txid)) != "" {
		t.Fatal("meta not pruned")
	}
	if store.Get(keyPageData(PagePayloadMap, sender, txid, 0)) != "" {
		t.Fatal("page not pruned")
	}
	if store.Get(keyPageIndex(height, 0)) != "" {
		t.Fatal("index not pruned")
	}
	if store.Get(keyPageCount(height)) != "" {
		t.Fatal("count not pruned")
	}
}

func TestPrunePagesForHeight_SkipsAlreadyReaped(t *testing.T) {
	store := NewInMemoryPageStore()
	height := uint32(222)
	txid := mustTxid(0x93)
	iv, _ := encodePageIndexValue(PagePayloadMap, "did:vsc:relay:r", txid)
	store.Set(keyPageIndex(height, 0), string(iv))
	writePageCount(store, height, 1)

	prunePagesForHeightStore(store, height)

	if store.Get(keyPageIndex(height, 0)) != "" {
		t.Fatal("index not removed")
	}
	if store.Get(keyPageCount(height)) != "" {
		t.Fatal("count not removed")
	}
}

func TestPrunePagesForHeight_SkipsUnsetBitmapSlots(t *testing.T) {
	store := NewInMemoryPageStore()
	height := uint32(333)
	txid := mustTxid(0x94)
	sender := "did:vsc:relay:s"
	meta := &pageMeta{TargetHeight: height, Total: 4, Bitmap: []byte{0b00000101}}
	store.Set(keyPageMeta(PagePayloadMap, sender, txid), string(encodeMeta(meta)))
	store.Set(keyPageData(PagePayloadMap, sender, txid, 0), "a")
	store.Set(keyPageData(PagePayloadMap, sender, txid, 2), "c")
	iv, _ := encodePageIndexValue(PagePayloadMap, sender, txid)
	store.Set(keyPageIndex(height, 0), string(iv))
	writePageCount(store, height, 1)

	prunePagesForHeightStore(store, height)

	if store.Get(keyPageData(PagePayloadMap, sender, txid, 1)) != "" {
		t.Fatal("unexpected key for unset bitmap slot")
	}
}

func TestWriteCount_SinglePagePlan_IsZero(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	store.Writes = 0
	_, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:w1", mustTxid(0xa1), 0, 5000, 0, 1, encodeForWire([]byte("one page")))
	if err != nil {
		t.Fatal(err)
	}
	if store.Writes != 0 {
		t.Fatalf("writes = %d, want 0", store.Writes)
	}
}

func TestWriteCount_ThreePagePlan_IsNine(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	store.Writes = 0
	payload := bytes.Repeat([]byte("z"), 10000)
	pages := splitPages(payload, 5000)
	if len(pages) != 3 {
		t.Fatalf("expected 3 pages, got %d", len(pages))
	}
	for i := range pages {
		if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:relay:w3", mustTxid(0xa2), 0, 5000, uint32(i), 3, []byte(pages[i])); err != nil {
			t.Fatal(err)
		}
	}
	if store.Writes != 9 {
		t.Fatalf("writes = %d, want 9", store.Writes)
	}
}

func TestSubmitPage_FrontRunResistance(t *testing.T) {
	store := NewInMemoryPageStore()
	withRetentionWindow(t, store, 5000)
	txid := mustTxid(0xa3)
	attackerPage := []byte("QUFB")
	if _, err := SubmitPage(store, PagePayloadMap, "did:vsc:attacker", txid, 0, 5000, 0, 128, attackerPage); err != nil {
		t.Fatal(err)
	}
	legitPayload := bytes.Repeat([]byte("L"), 6000)
	legitPages := splitPages(legitPayload, 3000)
	var assembled []byte
	for i := range legitPages {
		assembled, _ = SubmitPage(store, PagePayloadMap, "did:vsc:bot", txid, 0, 5000, uint32(i), uint32(len(legitPages)), []byte(legitPages[i]))
	}
	if !bytes.Equal(assembled, legitPayload) {
		t.Fatal("legit sender blocked by attacker lane")
	}
}

func TestSubmitPage_AbandonedPlanPrunedAtRetention(t *testing.T) {
	store := NewInMemoryPageStore()
	height := uint32(444)
	txid := mustTxid(0xa4)
	sender := "did:vsc:abandon"
	meta := &pageMeta{TargetHeight: height, Total: 3, Bitmap: []byte{0b00000011}}
	store.Set(keyPageMeta(PagePayloadMap, sender, txid), string(encodeMeta(meta)))
	store.Set(keyPageData(PagePayloadMap, sender, txid, 0), "a")
	store.Set(keyPageData(PagePayloadMap, sender, txid, 1), "b")
	iv, _ := encodePageIndexValue(PagePayloadMap, sender, txid)
	store.Set(keyPageIndex(height, 0), string(iv))
	var count [2]byte
	binary.LittleEndian.PutUint16(count[:], 1)
	store.Set(keyPageCount(height), string(count[:]))

	prunePagesForHeightStore(store, height)
	if store.Get(keyPageMeta(PagePayloadMap, sender, txid)) != "" || store.Get(keyPageCount(height)) != "" {
		t.Fatal("expected abandoned plan keys pruned")
	}
}
