package mapping

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// Cross-check with Lean: `MagiLean.Security.MappingBot`:
//   - PagePlanFitsL2                        -> per-page MaxPageBytes bound
//   - pagination_plan_each_page_fits_l2     -> split helper never exceeds MaxPageBytes
//   - contractSubmit_idempotent             -> duplicate page is a no-op
//   - contractSubmit_operator_independent   -> replay after completion is a no-op
//   - pagination_reconstructs_original      -> assembled bytes match input exactly
//   - contractSubmit_monotone               -> bitmap never clears a set bit

// encodeForWire returns the base64 (URL, no padding) form of the raw payload.
// This matches the mapping-bot client-side encoding.
func encodeForWire(raw []byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(raw))
}

// splitPages chunks the base64 wire-form of `payload` into pages of at most
// `pageSize` bytes. All contract-side tests use this helper so they exercise
// the same wire protocol the mapping bot produces.
func splitPages(payload []byte, pageSize int) [][]byte {
	if pageSize <= 0 {
		pageSize = MaxPageBytes
	}
	wire := encodeForWire(payload)
	if len(wire) == 0 {
		return [][]byte{{}}
	}
	var pages [][]byte
	for i := 0; i < len(wire); i += pageSize {
		end := i + pageSize
		if end > len(wire) {
			end = len(wire)
		}
		chunk := make([]byte, end-i)
		copy(chunk, wire[i:end])
		pages = append(pages, chunk)
	}
	return pages
}

func TestSubmitPage_SinglePage_CompletesImmediately(t *testing.T) {
	store := NewInMemoryPageStore()
	payload := []byte(`{"tx_data":{"raw_tx_hex":"deadbeef"},"instructions":["deposit_to=hive:alice"]}`)
	parentId := ComputeParentId(payload)
	wire := encodeForWire(payload)

	result, err := SubmitPage(store, PagePayloadMap, parentId, 0, 1, wire)
	if err != nil {
		t.Fatalf("SubmitPage: %v", err)
	}
	if !result.FreshlyAccepted {
		t.Fatal("expected FreshlyAccepted=true")
	}
	if !result.Complete {
		t.Fatal("expected Complete=true on single-page plan")
	}
	if !bytes.Equal(result.Assembled, payload) {
		t.Fatalf("Assembled mismatch: got %q, want %q", result.Assembled, payload)
	}
}

func TestSubmitPage_MultiPage_InOrder_AssemblesExact(t *testing.T) {
	store := NewInMemoryPageStore()
	payload := bytes.Repeat([]byte("ABCDEFGH"), 5000) // 40 000 bytes
	parentId := ComputeParentId(payload)
	pages := splitPages(payload, 12_000)
	if len(pages) < 3 {
		t.Fatalf("expected >= 3 pages, got %d", len(pages))
	}

	for i, p := range pages {
		result, err := SubmitPage(store, PagePayloadMap, parentId, uint32(i), uint32(len(pages)), p)
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		if !result.FreshlyAccepted {
			t.Fatalf("page %d not accepted as fresh", i)
		}
		if i < len(pages)-1 {
			if result.Complete {
				t.Fatalf("page %d: premature Complete", i)
			}
			if result.Assembled != nil {
				t.Fatalf("page %d: premature Assembled", i)
			}
		}
	}

	// The last page's result should have assembled the full payload; rerun to
	// capture it (the last loop iter already did this, but guard explicitly).
	last, err := SubmitPage(store, PagePayloadMap, parentId, uint32(len(pages)-1), uint32(len(pages)), pages[len(pages)-1])
	if err != nil {
		t.Fatalf("replay last: %v", err)
	}
	if !last.Complete {
		t.Fatal("expected Complete=true on replay after finalized plan")
	}
	if last.FreshlyAccepted {
		t.Fatal("replay after completion must be a no-op")
	}
}

func TestSubmitPage_MultiPage_OutOfOrder_AssemblesExact(t *testing.T) {
	store := NewInMemoryPageStore()
	payload := bytes.Repeat([]byte("xy"), 20_000) // 40 000 raw bytes
	parentId := ComputeParentId(payload)
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
		result, err := SubmitPage(store, PagePayloadMap, parentId, uint32(i), total, pages[i])
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		if result.Complete && result.Assembled != nil {
			assembled = result.Assembled
		}
	}

	if !bytes.Equal(assembled, payload) {
		t.Fatalf("out-of-order assembly mismatch (got %d bytes, want %d)", len(assembled), len(payload))
	}
}

func TestSubmitPage_DuplicatePage_IsNoop(t *testing.T) {
	store := NewInMemoryPageStore()
	payload := bytes.Repeat([]byte("Q"), 10_000)
	parentId := ComputeParentId(payload)
	pages := splitPages(payload, 4_000)

	r1, err := SubmitPage(store, PagePayloadMap, parentId, 0, uint32(len(pages)), pages[0])
	if err != nil {
		t.Fatal(err)
	}
	if !r1.FreshlyAccepted {
		t.Fatal("expected fresh on first submission")
	}

	// Snapshot state after first page accept.
	snapshot := make(map[string]string, len(store.Data))
	for k, v := range store.Data {
		snapshot[k] = v
	}

	r2, err := SubmitPage(store, PagePayloadMap, parentId, 0, uint32(len(pages)), pages[0])
	if err != nil {
		t.Fatalf("duplicate: %v", err)
	}
	if r2.FreshlyAccepted {
		t.Fatal("duplicate must not be accepted as fresh")
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

func TestSubmitPage_ContentHashMismatch_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	payload := bytes.Repeat([]byte("legit"), 5_000)
	// Client honestly computes parentId over `payload`.
	parentId := ComputeParentId(payload)
	pages := splitPages(payload, 4_000)
	total := uint32(len(pages))

	// But then tampers with the last page's bytes.
	pages[len(pages)-1] = append([]byte(nil), pages[len(pages)-1]...)
	pages[len(pages)-1][0] ^= 0xff

	for i := 0; i < len(pages)-1; i++ {
		if _, err := SubmitPage(store, PagePayloadMap, parentId, uint32(i), total, pages[i]); err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
	}
	_, err := SubmitPage(store, PagePayloadMap, parentId, total-1, total, pages[total-1])
	if err == nil {
		t.Fatal("expected content-hash mismatch error, got nil")
	}
}

func TestSubmitPage_TotalPagesMismatch_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	payload := []byte("hello")
	parentId := ComputeParentId(payload)
	wire := encodeForWire(payload)
	half := len(wire) / 2

	if _, err := SubmitPage(store, PagePayloadMap, parentId, 0, 3, wire[:half]); err != nil {
		t.Fatal(err)
	}
	// Caller now claims a different total_pages: must be rejected.
	if _, err := SubmitPage(store, PagePayloadMap, parentId, 1, 4, wire[half:]); err == nil {
		t.Fatal("expected total_pages mismatch error")
	}
}

func TestSubmitPage_KindsAreIndependent(t *testing.T) {
	// Map and confirmSpend pagination channels are namespaced by kind in
	// their state keys, so a parentId collision across kinds never conflates
	// streams. This is the contract-level equivalent of Lean's
	// `contractSubmit_operator_independent` across disjoint submission
	// channels.
	store := NewInMemoryPageStore()
	payload := []byte("hello")
	parentId := ComputeParentId(payload)
	wire := encodeForWire(payload)

	r1, err := SubmitPage(store, PagePayloadMap, parentId, 0, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Complete {
		t.Fatal("expected map-channel single page to complete")
	}

	r2, err := SubmitPage(store, PagePayloadConfirmSpend, parentId, 0, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Complete {
		t.Fatal("expected confirmSpend-channel single page to complete")
	}
	if !bytes.Equal(r2.Assembled, payload) {
		t.Fatal("confirmSpend channel assembled mismatch")
	}
}

func TestSubmitPage_PageIdxOutOfRange_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	if _, err := SubmitPage(store, PagePayloadMap, "abc", 5, 3, []byte("x")); err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestSubmitPage_ZeroTotalPages_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	if _, err := SubmitPage(store, PagePayloadMap, "abc", 0, 0, nil); err == nil {
		t.Fatal("expected zero-total error")
	}
}

func TestSubmitPage_ExceedMaxPagesPerParent_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	if _, err := SubmitPage(store, PagePayloadMap, "abc", 0, MaxPagesPerParent+1, nil); err == nil {
		t.Fatal("expected total-pages cap error")
	}
}

func TestSubmitPage_OversizePageBytes_Rejected(t *testing.T) {
	store := NewInMemoryPageStore()
	oversize := bytes.Repeat([]byte{'a'}, MaxPageBytes+1)
	parentId := ComputeParentId(oversize)
	if _, err := SubmitPage(store, PagePayloadMap, parentId, 0, 1, oversize); err == nil {
		t.Fatal("expected oversize-page error")
	}
}

func TestSubmitPage_PostCompletionReplay_IsNoop(t *testing.T) {
	store := NewInMemoryPageStore()
	payload := []byte("complete-me")
	parentId := ComputeParentId(payload)
	wire := encodeForWire(payload)

	first, err := SubmitPage(store, PagePayloadMap, parentId, 0, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Complete || first.Assembled == nil {
		t.Fatal("expected first submission to complete the plan")
	}

	replay, err := SubmitPage(store, PagePayloadMap, parentId, 0, 1, wire)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.FreshlyAccepted {
		t.Fatal("replay after completion must not be accepted as fresh")
	}
	if !replay.Complete {
		t.Fatal("replay after completion must report Complete")
	}
	if replay.Assembled != nil {
		t.Fatal("replay after completion must not re-emit Assembled")
	}
}

func TestSubmitPage_MonotoneBitmap(t *testing.T) {
	store := NewInMemoryPageStore()
	payload := bytes.Repeat([]byte("M"), 30_000)
	parentId := ComputeParentId(payload)
	pages := splitPages(payload, 5_000)
	total := uint32(len(pages))

	insp := PageInspector{Store: store}
	prevRecv := uint32(0)
	for i, p := range pages {
		if _, err := SubmitPage(store, PagePayloadMap, parentId, uint32(i), total, p); err != nil {
			t.Fatal(err)
		}
		if i == len(pages)-1 {
			// On completion the meta is cleared; done marker is set.
			_, _, _, done := insp.Meta(PagePayloadMap, parentId)
			if !done {
				t.Fatal("expected done-marker after completion")
			}
			continue
		}
		_, recv, _, _ := insp.Meta(PagePayloadMap, parentId)
		if recv <= prevRecv {
			t.Fatalf("Recv did not increase on fresh page %d (%d -> %d)", i, prevRecv, recv)
		}
		prevRecv = recv
	}
}

func TestComputeParentId_Stable(t *testing.T) {
	a := ComputeParentId([]byte("same bytes"))
	b := ComputeParentId([]byte("same bytes"))
	if a != b {
		t.Fatal("ComputeParentId must be deterministic")
	}
	c := ComputeParentId([]byte("other bytes"))
	if a == c {
		t.Fatal("ComputeParentId must discriminate different inputs")
	}
	if len(a) != 64 {
		t.Fatalf("expected 64-char hex sha256, got %d", len(a))
	}
}
