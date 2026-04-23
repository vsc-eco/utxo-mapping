package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

type PagePayloadKind uint8

const (
	PagePayloadMap          PagePayloadKind = 1
	PagePayloadConfirmSpend PagePayloadKind = 2
)

type PageStore interface {
	Get(key string) string
	Set(key, value string)
	Delete(key string)
}

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

type pageMeta struct {
	TargetHeight uint32
	Total        uint8
	Bitmap       []byte
}

func (m *pageMeta) hasPage(idx uint32) bool {
	byteIdx := idx / 8
	if int(byteIdx) >= len(m.Bitmap) {
		return false
	}
	return m.Bitmap[byteIdx]&(byte(1)<<(idx%8)) != 0
}

func (m *pageMeta) setPage(idx uint32) {
	byteIdx := idx / 8
	m.Bitmap[byteIdx] |= byte(1) << (idx % 8)
}

func (m *pageMeta) recvCount() uint32 {
	var n uint32
	for _, b := range m.Bitmap {
		n += uint32(popcount8(b))
	}
	return n
}

func popcount8(v byte) uint8 {
	var n uint8
	for v != 0 {
		v &= v - 1
		n++
	}
	return n
}

func encodeMeta(m *pageMeta) []byte {
	out := make([]byte, 5+len(m.Bitmap))
	binary.LittleEndian.PutUint32(out[:4], m.TargetHeight)
	out[4] = m.Total
	copy(out[5:], m.Bitmap)
	return out
}

func decodeMeta(raw []byte) (*pageMeta, error) {
	if len(raw) < 5 {
		return nil, ce.NewContractError(ce.ErrInput, "page meta too short")
	}
	total := raw[4]
	if total == 0 || uint32(total) > constants.MaxPagesPerPlan {
		return nil, ce.NewContractError(ce.ErrInput, "page meta total out of range")
	}
	wantBitmap := int((uint32(total) + 7) / 8)
	if len(raw[5:]) != wantBitmap {
		return nil, ce.NewContractError(ce.ErrInput, "page meta bitmap size mismatch")
	}
	return &pageMeta{
		TargetHeight: binary.LittleEndian.Uint32(raw[:4]),
		Total:        total,
		Bitmap:       append([]byte(nil), raw[5:]...),
	}, nil
}

func retainFrom(lastHeight uint32) uint32 {
	if lastHeight < constants.MaxBlockRetention {
		return 0
	}
	return lastHeight - constants.MaxBlockRetention + 1
}

func keyPageData(kind PagePayloadKind, sender string, txid [32]byte, idx uint16) string {
	b := make([]byte, 0, 1+1+len(sender)+1+32+2)
	b = append(b, constants.PageDataPrefix[0], byte(kind))
	b = append(b, sender...)
	b = append(b, 0)
	b = append(b, txid[:]...)
	var idxBytes [2]byte
	binary.LittleEndian.PutUint16(idxBytes[:], idx)
	b = append(b, idxBytes[:]...)
	return string(b)
}

func keyPageMeta(kind PagePayloadKind, sender string, txid [32]byte) string {
	b := make([]byte, 0, 1+1+len(sender)+1+32)
	b = append(b, constants.PageMetaPrefix[0], byte(kind))
	b = append(b, sender...)
	b = append(b, 0)
	b = append(b, txid[:]...)
	return string(b)
}

func keyPageIndex(height uint32, pos uint16) string {
	var b [7]byte
	b[0] = constants.PageIndexPrefix[0]
	binary.LittleEndian.PutUint32(b[1:5], height)
	binary.LittleEndian.PutUint16(b[5:7], pos)
	return string(b[:])
}

func keyPageCount(height uint32) string {
	var b [5]byte
	b[0] = constants.PageCountPrefix[0]
	binary.LittleEndian.PutUint32(b[1:5], height)
	return string(b[:])
}

func encodePageIndexValue(kind PagePayloadKind, sender string, txid [32]byte) ([]byte, error) {
	if len(sender) > 255 {
		return nil, ce.NewContractError(ce.ErrInput, "sender too long")
	}
	out := make([]byte, 0, 1+1+len(sender)+32)
	out = append(out, byte(kind), byte(len(sender)))
	out = append(out, sender...)
	out = append(out, txid[:]...)
	return out, nil
}

func decodePageIndexValue(raw []byte) (kind PagePayloadKind, sender string, txid [32]byte, err error) {
	if len(raw) < 34 {
		err = ce.NewContractError(ce.ErrInput, "page index entry too short")
		return
	}
	kind = PagePayloadKind(raw[0])
	senderLen := int(raw[1])
	if len(raw) != 2+senderLen+32 {
		err = ce.NewContractError(ce.ErrInput, "page index entry malformed")
		return
	}
	sender = string(raw[2 : 2+senderLen])
	copy(txid[:], raw[2+senderLen:])
	return
}

func txidHex(txid [32]byte) string {
	return hex.EncodeToString(txid[:])
}

func readPageCount(store PageStore, height uint32) uint16 {
	raw := store.Get(keyPageCount(height))
	if len(raw) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16([]byte(raw)[:2])
}

func writePageCount(store PageStore, height uint32, count uint16) {
	var out [2]byte
	binary.LittleEndian.PutUint16(out[:], count)
	store.Set(keyPageCount(height), string(out[:]))
}

func SubmitPage(
	store PageStore,
	kind PagePayloadKind,
	sender string,
	txid [32]byte,
	vout, blockHeight, pageIdx, totalPages uint32,
	data []byte,
) ([]byte, error) {
	if sender == "" {
		return nil, ce.NewContractError(ce.ErrInput, "sender required")
	}
	if vout > 65535 {
		return nil, ce.NewContractError(ce.ErrInput, "vout exceeds uint16 range")
	}
	if totalPages == 0 {
		return nil, ce.NewContractError(ce.ErrInput, "total_pages must be > 0")
	}
	if totalPages > constants.MaxPagesPerPlan {
		return nil, ce.NewContractError(ce.ErrInput, "total_pages exceeds MaxPagesPerPlan")
	}
	if pageIdx >= totalPages {
		return nil, ce.NewContractError(ce.ErrInput, "page_idx out of range")
	}
	if len(data)%4 == 1 {
		return nil, ce.NewContractError(ce.ErrInput, "invalid base64 payload length")
	}
	if pageIdx != totalPages-1 && len(data)%4 != 0 {
		return nil, ce.NewContractError(ce.ErrInput, "non-final pages must be 4-char aligned")
	}

	lastHeightRaw := store.Get(constants.LastHeightKey)
	if lastHeightRaw == "" {
		return nil, ce.NewContractError(ce.ErrStateAccess, "missing last block height")
	}
	lastHeight64, err := strconv.ParseUint(lastHeightRaw, 10, 32)
	if err != nil {
		return nil, ce.NewContractError(ce.ErrStateAccess, "invalid last block height")
	}
	lastHeight := uint32(lastHeight64)
	minHeight := retainFrom(lastHeight)
	if blockHeight < minHeight || blockHeight > lastHeight {
		return nil, ce.NewContractError(ce.ErrInput, "block_height outside retained window")
	}

	entry, err := makeObservedEntry(txidHex(txid), vout)
	if err != nil {
		return nil, ce.NewContractError(ce.ErrInput, "invalid txid for observed check")
	}
	if isObserved(loadObservedListFromStore(store, blockHeight), entry) {
		return nil, ce.NewContractError(ce.ErrInput, "tx output already observed")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, ce.NewContractError(ce.ErrInput, "page payload base64 decode failed")
	}
	if len(decoded) > constants.MaxRawPageBytes {
		return nil, ce.NewContractError(ce.ErrInput, "decoded page exceeds MaxRawPageBytes")
	}

	if totalPages == 1 {
		return decoded, nil
	}

	metaKey := keyPageMeta(kind, sender, txid)
	var meta *pageMeta
	metaRaw := store.Get(metaKey)
	metaExisted := metaRaw != ""
	if metaExisted {
		meta, err = decodeMeta([]byte(metaRaw))
		if err != nil {
			return nil, err
		}
		if pageIdx == 0 && (meta.TargetHeight != blockHeight || uint32(meta.Total) != totalPages) {
			for i := uint32(0); i < uint32(meta.Total); i++ {
				if meta.hasPage(i) {
					store.Delete(keyPageData(kind, sender, txid, uint16(i)))
				}
			}
			store.Delete(metaKey)
			meta = nil
			metaExisted = false
		}
	}

	if !metaExisted {
		count := readPageCount(store, blockHeight)
		if uint32(count) >= constants.MaxPlansPerHeight {
			return nil, ce.NewContractError(ce.ErrInput, "max plans per height exceeded")
		}
		iv, err := encodePageIndexValue(kind, sender, txid)
		if err != nil {
			return nil, err
		}
		store.Set(keyPageIndex(blockHeight, count), string(iv))
		writePageCount(store, blockHeight, count+1)
		meta = &pageMeta{
			TargetHeight: blockHeight,
			Total:        uint8(totalPages),
			Bitmap:       make([]byte, (totalPages+7)/8),
		}
	} else if pageIdx != 0 && (meta.TargetHeight != blockHeight || uint32(meta.Total) != totalPages) {
		return nil, ce.NewContractError(ce.ErrInput, "page metadata mismatch")
	}

	if meta.hasPage(pageIdx) {
		return nil, nil
	}

	prevBitmap := append([]byte(nil), meta.Bitmap...)
	meta.setPage(pageIdx)
	if meta.recvCount() < totalPages {
		store.Set(keyPageData(kind, sender, txid, uint16(pageIdx)), string(decoded))
		store.Set(metaKey, string(encodeMeta(meta)))
		return nil, nil
	}

	parts := make([][]byte, totalPages)
	parts[pageIdx] = decoded
	totalLen := len(decoded)
	for i := uint32(0); i < totalPages; i++ {
		if i == pageIdx {
			continue
		}
		byteIdx := i / 8
		mask := byte(1) << (i % 8)
		if prevBitmap[byteIdx]&mask == 0 {
			return nil, ce.NewContractError(ce.ErrInput, "missing page during final assembly")
		}
		chunk := store.Get(keyPageData(kind, sender, txid, uint16(i)))
		if chunk == "" {
			return nil, ce.NewContractError(ce.ErrInput, "missing page data during final assembly")
		}
		parts[i] = []byte(chunk)
		totalLen += len(parts[i])
	}
	assembled := make([]byte, 0, totalLen)
	for i := uint32(0); i < totalPages; i++ {
		assembled = append(assembled, parts[i]...)
	}

	for i := uint32(0); i < totalPages; i++ {
		if i == pageIdx {
			continue
		}
		store.Delete(keyPageData(kind, sender, txid, uint16(i)))
	}
	store.Delete(metaKey)
	return assembled, nil
}

func loadObservedListFromStore(store PageStore, blockHeight uint32) []observedEntry {
	raw := store.Get(observedBlockKey(blockHeight))
	if len(raw) == 0 {
		return nil
	}
	data := []byte(raw)
	if len(data)%observedEntrySize != 0 {
		return nil
	}
	out := make([]observedEntry, len(data)/observedEntrySize)
	for i := range out {
		copy(out[i][:], data[i*observedEntrySize:(i+1)*observedEntrySize])
	}
	return out
}

func PrunePagesForHeight(height uint32) {
	store := SdkPageStore{}
	prunePagesForHeightStore(store, height)
}

func prunePagesForHeightStore(store PageStore, height uint32) {
	countKey := keyPageCount(height)
	countRaw := store.Get(countKey)
	if countRaw == "" {
		return
	}
	count := readPageCount(store, height)
	if count == 0 {
		store.Delete(countKey)
		return
	}

	for pos := uint16(0); pos < count; pos++ {
		indexKey := keyPageIndex(height, pos)
		raw := store.Get(indexKey)
		if raw == "" {
			continue
		}
		kind, sender, txid, err := decodePageIndexValue([]byte(raw))
		if err != nil {
			store.Delete(indexKey)
			continue
		}
		metaKey := keyPageMeta(kind, sender, txid)
		metaRaw := store.Get(metaKey)
		if metaRaw == "" {
			store.Delete(indexKey)
			continue
		}
		meta, err := decodeMeta([]byte(metaRaw))
		if err != nil {
			store.Delete(metaKey)
			store.Delete(indexKey)
			continue
		}
		for i := uint32(0); i < uint32(meta.Total); i++ {
			if meta.hasPage(i) {
				store.Delete(keyPageData(kind, sender, txid, uint16(i)))
			}
		}
		store.Delete(metaKey)
		store.Delete(indexKey)
	}

	store.Delete(countKey)
}
