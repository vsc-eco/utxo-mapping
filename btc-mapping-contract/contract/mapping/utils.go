package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/bits"
	"slices"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func createP2WSHAddressWithBackup(
	primaryPubKey CompressedPubKey, backupPubKey CompressedPubKey, tag []byte, network *chaincfg.Params,
) (string, []byte, error) {
	csvBlocks := constants.BackupCSVBlocks

	if network.Net != chaincfg.MainNetParams.Net {
		csvBlocks = constants.TestnetBackupCSVBlocks
	}

	scriptBuilder := txscript.NewScriptBuilder()

	// start if
	scriptBuilder.AddOp(txscript.OP_IF)

	// primary spending path
	// uses OP_CHECKSIG instead of OP_CHECKSIGVERIFY for tags of length 0
	// because an empty tag will leave the stack empty after verificaiton
	// and the tx will fail
	scriptBuilder.AddData(primaryPubKey[:])
	if len(tag) > 0 {
		scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY)
		scriptBuilder.AddData(tag)
	} else {
		scriptBuilder.AddOp(txscript.OP_CHECKSIG)
	}

	// else: backup path
	scriptBuilder.AddOp(txscript.OP_ELSE)

	scriptBuilder.AddInt64(int64(csvBlocks))
	scriptBuilder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	scriptBuilder.AddOp(txscript.OP_DROP)

	scriptBuilder.AddData(backupPubKey[:])
	scriptBuilder.AddOp(txscript.OP_CHECKSIG)

	// end if
	scriptBuilder.AddOp(txscript.OP_ENDIF)

	script, err := scriptBuilder.Script()
	if err != nil {
		return "", nil, err
	}

	witnessProgram := sha256.Sum256(script)
	addressWitnessScriptHash, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], network)
	if err != nil {
		return "", nil, err
	}

	return addressWitnessScriptHash.EncodeAddress(), script, nil
}

func createP2WSHAddress(pubKeyHex string, tag []byte, network *chaincfg.Params) (string, []byte, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", nil, err
	}

	return createSimpleP2WSHAddress(pubKeyBytes, tag, network)
}

func createSimpleP2WSHAddress(pubKeyBytes []byte, tag []byte, network *chaincfg.Params) (string, []byte, error) {
	scriptBuilder := txscript.NewScriptBuilder()
	if len(tag) > 0 {
		scriptBuilder.AddData(pubKeyBytes)
		scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY)
		scriptBuilder.AddData(tag)
	} else {
		scriptBuilder.AddData(pubKeyBytes)
		scriptBuilder.AddOp(txscript.OP_CHECKSIG)
	}

	script, err := scriptBuilder.Script()
	if err != nil {
		return "", nil, err
	}

	witnessProgram := sha256.Sum256(script)
	addressWitnessScriptHash, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], network)
	if err != nil {
		return "", nil, err
	}
	return addressWitnessScriptHash.EncodeAddress(), script, nil
}

func checkAuth(env sdk.Env) error {
	if !slices.Contains(env.Sender.RequiredAuths, env.Sender.Address) {
		return ce.NewContractError(ce.ErrNoPermission, "active auth required to send funds")
	}
	return nil
}

func checkAndDeductBalance(env sdk.Env, account string, amount int64) error {
	callerAddress := env.Caller.String()
	bal := getAccBal(account)
	if bal < amount {
		return ce.NewContractError(
			ce.ErrBalance,
			"account ["+account+"] balance "+strconv.FormatInt(bal, 10)+
				" insufficient needs "+strconv.FormatInt(amount, 10),
		)
	}
	if account != callerAddress {
		allowance := getAllowance(account, callerAddress)
		if allowance < amount {
			return ce.NewContractError(
				ce.ErrNoPermission,
				"allowance ("+strconv.FormatInt(allowance, 10)+
					") insufficient for spend ("+strconv.FormatInt(amount, 10)+
					") by "+callerAddress,
			)
		}
		setAllowance(account, callerAddress, allowance-amount)
	}
	newBal, err := safeSubtract64(bal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error decrementing user balance")
	}
	setAccBal(account, newBal)
	return nil
}

// ---------------------------------------------------------------------------
// UTXO registry binary encoding (9 bytes/entry: 1 byte ID + 8 bytes amount BE)
// ID 0–63 = unconfirmed pool; ID 64–255 = confirmed pool.
// ---------------------------------------------------------------------------

func MarshalUtxoRegistry(r UtxoRegistry) []byte {
	buf := make([]byte, len(r)*8)
	var tmp [8]byte
	for i, e := range r {
		off := i * 8
		binary.BigEndian.PutUint16(buf[off:], e.Id)
		binary.BigEndian.PutUint64(tmp[:], uint64(e.Amount))
		copy(buf[off+2:off+8], tmp[2:]) // lower 6 bytes
	}
	return buf
}

func UnmarshalUtxoRegistry(data []byte) (UtxoRegistry, error) {
	if len(data)%8 != 0 {
		return nil, errors.New("invalid utxo registry: length not a multiple of 8")
	}
	out := make(UtxoRegistry, len(data)/8)
	var tmp [8]byte
	for i := range out {
		off := i * 8
		out[i].Id = binary.BigEndian.Uint16(data[off:])
		copy(tmp[2:], data[off+2:off+8])
		tmp[0] = 0
		tmp[1] = 0
		out[i].Amount = int64(binary.BigEndian.Uint64(tmp[:]))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Vault registry binary encoding (VaultEntrySize=91 bytes/entry) — S1 dual-gen + S5 InactiveHeight.
// Mirrors the UtxoRegistry packed-blob idiom. See types.go Vault for the layout.
// ---------------------------------------------------------------------------

func MarshalVaultRegistry(v VaultRegistry) []byte {
	buf := make([]byte, len(v)*VaultEntrySize)
	for i := range v {
		off := i * VaultEntrySize
		e := &v[i]
		binary.BigEndian.PutUint32(buf[off:], e.Generation)
		copy(buf[off+4:off+37], e.Primary[:])
		copy(buf[off+37:off+70], e.Backup[:])
		buf[off+70] = byte(e.Status)
		binary.BigEndian.PutUint32(buf[off+71:], e.Predecessor)
		binary.BigEndian.PutUint32(buf[off+75:], e.CreatedHeight)
		binary.BigEndian.PutUint32(buf[off+79:], e.ActivatedHeight)
		binary.BigEndian.PutUint32(buf[off+83:], e.RetiredHeight)
		binary.BigEndian.PutUint32(buf[off+87:], e.InactiveHeight)
	}
	return buf
}

func UnmarshalVaultRegistry(data []byte) (VaultRegistry, error) {
	if len(data)%VaultEntrySize != 0 {
		return nil, errors.New("invalid vault registry: length not a multiple of VaultEntrySize")
	}
	out := make(VaultRegistry, len(data)/VaultEntrySize)
	for i := range out {
		off := i * VaultEntrySize
		out[i].Generation = binary.BigEndian.Uint32(data[off:])
		copy(out[i].Primary[:], data[off+4:off+37])
		copy(out[i].Backup[:], data[off+37:off+70])
		out[i].Status = VaultStatus(data[off+70])
		out[i].Predecessor = binary.BigEndian.Uint32(data[off+71:])
		out[i].CreatedHeight = binary.BigEndian.Uint32(data[off+75:])
		out[i].ActivatedHeight = binary.BigEndian.Uint32(data[off+79:])
		out[i].RetiredHeight = binary.BigEndian.Uint32(data[off+83:])
		out[i].InactiveHeight = binary.BigEndian.Uint32(data[off+87:])
	}
	return out, nil
}

// VaultKeyId returns the TSS keyId for a vault generation. Generation 0 keeps the
// legacy "main" id (backward-compatible with the live deployed key); generation N
// uses "mainv<N>". The node prefixes the contract id and its isBtcVaultKey gate
// prefix-matches "main" for every generation. Exported: the key ceremony in main.go
// (createKey/renewKey) mints/renews keys by generation and MUST use this single
// source of truth — never re-derive the id inline (drift would strand a gen's key).
//
// The id MUST be alphanumeric (^[a-zA-Z0-9]+$): the runtime's tss create_key /
// tss_v2.create_key / renew_key host bindings reject any other keyName with
// ErrInvalidArgument. A hyphenated "main-v<N>" would be rejected at keygen time —
// rotation would be impossible (a latent brick). Hence "mainv<N>", no separator.
func VaultKeyId(gen uint32) string {
	if gen == 0 {
		return constants.TssKeyName
	}
	return constants.TssKeyName + "v" + strconv.FormatUint(uint64(gen), 10)
}

// isZeroKey reports whether a compressed pubkey is the zero value — i.e. a vault
// whose TSS keygen has not yet landed a real key. Activation MUST refuse a
// zero-key vault (its address would be underivable / unspendable).
func isZeroKey(k CompressedPubKey) bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// vaultKeysForGeneration returns the primary+backup pubkeys of the given vault
// generation from the loaded vault list, and whether the generation was FOUND.
// The caller MUST check `found`: falling back to cs.PublicKeys is only safe when
// the vault list is empty (pre-fold — everything is gen-0/legacy). For a missing
// generation in a POPULATED list the caller must ABORT, because vaultKeyId does
// NOT fall back (it returns "mainv<N>") — a silent key-fallback would build a
// witness the signature cannot satisfy → an unspendable tx (council F2, 3-lens).
func (cs *ContractState) vaultKeysForGeneration(gen uint32) (CompressedPubKey, CompressedPubKey, bool) {
	for i := range cs.Vaults {
		if cs.Vaults[i].Generation == gen {
			return cs.Vaults[i].Primary, cs.Vaults[i].Backup, true
		}
	}
	return cs.PublicKeys.Primary, cs.PublicKeys.Backup, false
}

// ---------------------------------------------------------------------------
// Individual UTXO binary encoding
//
// Layout:
//   [32] TxId bytes  (hex.DecodeString of display-hex txid)
//   [4]  Vout        (uint32 BE)
//   [8]  Amount      (int64  BE)
//   [1]  len(PkScript)
//   [N]  PkScript
//   [1]  len(Tag)
//   [M]  Tag
//   [4]  Generation  (uint32 BE; S1 dual-gen; absent in pre-S1 blobs → read as 0)
// ---------------------------------------------------------------------------

func MarshalUtxo(u *Utxo) []byte {
	txIdBytes, err := hex.DecodeString(u.TxId)
	if err != nil || len(txIdBytes) != 32 {
		return nil
	}
	total := 32 + 4 + 8 + 1 + len(u.PkScript) + 1 + len(u.Tag) + 4 // +4: Generation (S1 dual-gen)
	buf := make([]byte, total)
	off := 0
	copy(buf[off:], txIdBytes)
	off += 32
	binary.BigEndian.PutUint32(buf[off:], u.Vout)
	off += 4
	binary.BigEndian.PutUint64(buf[off:], uint64(u.Amount))
	off += 8
	buf[off] = byte(len(u.PkScript))
	off++
	copy(buf[off:], u.PkScript)
	off += len(u.PkScript)
	buf[off] = byte(len(u.Tag))
	off++
	copy(buf[off:], u.Tag)
	off += len(u.Tag)
	binary.BigEndian.PutUint32(buf[off:], u.Generation)
	return buf
}

func UnmarshalUtxo(data []byte) (*Utxo, error) {
	const minLen = 32 + 4 + 8 + 1 + 1
	if len(data) < minLen {
		return nil, errors.New("utxo data too short")
	}
	u := &Utxo{}
	off := 0
	u.TxId = hex.EncodeToString(data[off : off+32])
	off += 32
	u.Vout = binary.BigEndian.Uint32(data[off:])
	off += 4
	u.Amount = int64(binary.BigEndian.Uint64(data[off:]))
	off += 8
	pkLen := int(data[off])
	off++
	if off+pkLen > len(data) {
		return nil, errors.New("utxo data truncated (pkscript)")
	}
	u.PkScript = make([]byte, pkLen)
	copy(u.PkScript, data[off:off+pkLen])
	off += pkLen
	if off >= len(data) {
		return nil, errors.New("utxo data truncated (tag len)")
	}
	tagLen := int(data[off])
	off++
	if off+tagLen > len(data) {
		return nil, errors.New("utxo data truncated (tag)")
	}
	u.Tag = make([]byte, tagLen)
	copy(u.Tag, data[off:off+tagLen])
	off += tagLen
	// S1 dual-gen: Generation (4 bytes BE) is appended. A pre-S1 blob ends here (no
	// tail → gen 0); an S1 blob has EXACTLY 4 trailing bytes. Any other remainder is a
	// corrupt/truncated blob → fail closed (D-CLOSE-1), matching the pkscript/tag length
	// checks above, rather than silently reading gen 0.
	switch rem := len(data) - off; rem {
	case 0: // pre-S1 blob — generation stays 0
	case 4:
		u.Generation = binary.BigEndian.Uint32(data[off:])
	default:
		return nil, errors.New("utxo data has a malformed generation tail")
	}
	return u, nil
}

func loadUtxo(id uint16) (*Utxo, error) {
	raw := sdk.StateGetObject(getUtxoKey(id))
	if raw == nil || *raw == "" {
		return nil, ce.NewContractError(ce.ErrStateAccess, "utxo not found for id "+strconv.Itoa(int(id)))
	}
	u, err := UnmarshalUtxo([]byte(*raw))
	if err != nil {
		return nil, ce.NewContractError(ce.ErrStateAccess, "error deserialising utxo: "+err.Error())
	}
	return u, nil
}

func saveUtxo(id uint16, u *Utxo) {
	sdk.StateSetObject(getUtxoKey(id), string(MarshalUtxo(u)))
}

// ---------------------------------------------------------------------------
// SystemSupply binary encoding — 32 bytes, four int64 BE values.
// ---------------------------------------------------------------------------

func MarshalSupply(s *SystemSupply) []byte {
	var buf [32]byte
	binary.BigEndian.PutUint64(buf[0:], uint64(s.ActiveSupply))
	binary.BigEndian.PutUint64(buf[8:], uint64(s.UserSupply))
	binary.BigEndian.PutUint64(buf[16:], uint64(s.FeeSupply))
	binary.BigEndian.PutUint64(buf[24:], uint64(s.BaseFeeRate))
	return buf[:]
}

func UnmarshalSupply(data []byte) (*SystemSupply, error) {
	if len(data) != 32 {
		return nil, errors.New("invalid supply data: expected 32 bytes")
	}
	return &SystemSupply{
		ActiveSupply: int64(binary.BigEndian.Uint64(data[0:])),
		UserSupply:   int64(binary.BigEndian.Uint64(data[8:])),
		FeeSupply:    int64(binary.BigEndian.Uint64(data[16:])),
		BaseFeeRate:  int64(binary.BigEndian.Uint64(data[24:])),
	}, nil
}

// MarshalSigningData encodes SigningData as MessagePack.
func MarshalSigningData(sd *SigningData) ([]byte, error) {
	return sd.MarshalMsg(nil)
}

// UnmarshalSigningData decodes MessagePack-encoded SigningData.
func UnmarshalSigningData(data []byte) (*SigningData, error) {
	var sd SigningData
	_, err := sd.UnmarshalMsg(data)
	if err != nil {
		return nil, err
	}
	return &sd, nil
}

// ---------------------------------------------------------------------------
// TxSpendsRegistry binary encoding — 32 bytes per display-hex txid.
// ---------------------------------------------------------------------------

func MarshalTxSpendsRegistry(ts TxSpendsRegistry) []byte {
	buf := make([]byte, len(ts)*32)
	for i, txId := range ts {
		decoded, err := hex.DecodeString(txId)
		if err != nil || len(decoded) != 32 {
			return nil
		}
		copy(buf[i*32:], decoded)
	}
	return buf
}

func UnmarshalTxSpendsRegistry(data []byte) (TxSpendsRegistry, error) {
	if len(data)%32 != 0 {
		return nil, errors.New("invalid tx spends registry: length not a multiple of 32")
	}
	out := make(TxSpendsRegistry, len(data)/32)
	for i := range out {
		out[i] = hex.EncodeToString(data[i*32 : i*32+32])
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// MigrationSweep record binary encoding (BRK-1 delete-at-confirm). State key
// "ms-"+txId, one record per in-flight migration sweep. Layout:
//
//	[8]   BtcFee            (int64  BE; the reserved miner fee, always >= 0)
//	[4]   SuccessorGen      (uint32 BE)
//	[2]   len(InputIds)     (uint16 BE; bounded by MaxMigrationInputs)
//	[2*N] InputIds          (uint16 BE each)
//	[M]   SuccessorAddress  (UTF-8, the record tail — no length prefix)
// ---------------------------------------------------------------------------

func MarshalMigrationSweep(r *MigrationSweep) []byte {
	n := len(r.InputIds)
	buf := make([]byte, 8+4+4+2+n*2+len(r.SuccessorAddress))
	off := 0
	binary.BigEndian.PutUint64(buf[off:], uint64(r.BtcFee))
	off += 8
	binary.BigEndian.PutUint32(buf[off:], r.SuccessorGen)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], r.BuildHeight) // L7-01
	off += 4
	binary.BigEndian.PutUint16(buf[off:], uint16(n))
	off += 2
	for _, id := range r.InputIds {
		binary.BigEndian.PutUint16(buf[off:], id)
		off += 2
	}
	copy(buf[off:], r.SuccessorAddress)
	return buf
}

func UnmarshalMigrationSweep(data []byte) (*MigrationSweep, error) {
	const minLen = 8 + 4 + 4 + 2
	if len(data) < minLen {
		return nil, errors.New("migration sweep record too short")
	}
	r := &MigrationSweep{}
	off := 0
	r.BtcFee = int64(binary.BigEndian.Uint64(data[off:]))
	off += 8
	r.SuccessorGen = binary.BigEndian.Uint32(data[off:])
	off += 4
	r.BuildHeight = binary.BigEndian.Uint32(data[off:]) // L7-01
	off += 4
	n := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if off+n*2 > len(data) {
		return nil, errors.New("migration sweep record truncated (input ids)")
	}
	r.InputIds = make([]uint16, n)
	for i := 0; i < n; i++ {
		r.InputIds[i] = binary.BigEndian.Uint16(data[off:])
		off += 2
	}
	r.SuccessorAddress = string(data[off:])
	return r, nil
}

// ---------------------------------------------------------------------------
// PendingUnmap record ("us-"+txId) — Guard 1 delete-at-confirm. Layout:
//
//	[4]   ChangeGen     (uint32 BE)
//	[2]   len(InputIds) (uint16 BE)
//	[2*N] InputIds      (uint16 BE each)
//	[M]   ChangeAddress (UTF-8, the record tail — no length prefix)
// ---------------------------------------------------------------------------

func MarshalPendingUnmap(r *PendingUnmap) []byte {
	n := len(r.InputIds)
	buf := make([]byte, 4+8+4+2+n*2+len(r.ChangeAddress))
	off := 0
	binary.BigEndian.PutUint32(buf[off:], r.ChangeGen)
	off += 4
	binary.BigEndian.PutUint64(buf[off:], uint64(r.BtcFee)) // L7-01
	off += 8
	binary.BigEndian.PutUint32(buf[off:], r.BuildHeight) // L7-01
	off += 4
	binary.BigEndian.PutUint16(buf[off:], uint16(n))
	off += 2
	for _, id := range r.InputIds {
		binary.BigEndian.PutUint16(buf[off:], id)
		off += 2
	}
	copy(buf[off:], r.ChangeAddress)
	return buf
}

func UnmarshalPendingUnmap(data []byte) (*PendingUnmap, error) {
	const minLen = 4 + 8 + 4 + 2
	if len(data) < minLen {
		return nil, errors.New("pending unmap record too short")
	}
	r := &PendingUnmap{}
	off := 0
	r.ChangeGen = binary.BigEndian.Uint32(data[off:])
	off += 4
	r.BtcFee = int64(binary.BigEndian.Uint64(data[off:])) // L7-01
	off += 8
	r.BuildHeight = binary.BigEndian.Uint32(data[off:]) // L7-01
	off += 4
	n := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if off+n*2 > len(data) {
		return nil, errors.New("pending unmap record truncated (input ids)")
	}
	r.InputIds = make([]uint16, n)
	for i := 0; i < n; i++ {
		r.InputIds[i] = binary.BigEndian.Uint16(data[off:])
		off += 2
	}
	r.ChangeAddress = string(data[off:])
	return r, nil
}

// ---------------------------------------------------------------------------
// SpendGroup record ("g-"+<minInputId>) — L7-01 re-drive spend group. Layout:
//
//	[8]    HighestFee     (int64 BE)
//	[2]    len(Members)   (uint16 BE)
//	[64*K] Members        (64-char hex txids, fixed width, no delimiters)
// ---------------------------------------------------------------------------

const txidHexLen = 64

func MarshalSpendGroup(g *SpendGroup) []byte {
	k := len(g.Members)
	buf := make([]byte, 8+2+k*txidHexLen)
	off := 0
	binary.BigEndian.PutUint64(buf[off:], uint64(g.HighestFee))
	off += 8
	binary.BigEndian.PutUint16(buf[off:], uint16(k))
	off += 2
	for _, m := range g.Members {
		copy(buf[off:off+txidHexLen], m) // txids are always 64 hex chars
		off += txidHexLen
	}
	return buf
}

func UnmarshalSpendGroup(data []byte) (*SpendGroup, error) {
	const minLen = 8 + 2
	if len(data) < minLen {
		return nil, errors.New("spend group record too short")
	}
	g := &SpendGroup{}
	off := 0
	g.HighestFee = int64(binary.BigEndian.Uint64(data[off:]))
	off += 8
	k := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if off+k*txidHexLen != len(data) {
		return nil, errors.New("spend group record truncated (members)")
	}
	g.Members = make([]string, k)
	for i := 0; i < k; i++ {
		g.Members[i] = string(data[off : off+txidHexLen])
		off += txidHexLen
	}
	return g, nil
}

// spendGroupKey derives the L7-01 spend-group state key from a spend's reserved input
// set: "g-"+<minInputId>. Deterministic and stable across an original spend and its
// re-driven replacements (they reuse the IDENTICAL inputs), and unique because a UTXO is
// reserved by at most one live spend. Panics on an empty set — callers always have ≥1 input.
func spendGroupKey(inputIds []uint16) string {
	min := inputIds[0]
	for _, id := range inputIds[1:] {
		if id < min {
			min = id
		}
	}
	return constants.SpendGroupPrefix + strconv.FormatUint(uint64(min), 10)
}

// currentLastHeight reads the deterministic LastHeight ("h") — the same value the
// blocklist package writes at addBlocks/seedBlocks — for the L7-01 record BuildHeight and
// re-drive staleness gate. 0 if unset (pre-genesis) or unparseable, treated as "oldest".
func currentLastHeight() uint32 {
	raw := sdk.StateGetObject(constants.LastHeightKey)
	if raw == nil || *raw == "" {
		return 0
	}
	h, err := strconv.ParseUint(*raw, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(h)
}

// removeTxid swap-removes txId from a txid list (TxSpendsList / MigrationSweeps),
// membership-only so order does not matter. Returns the (possibly shortened) slice.
func removeTxid(list []string, txId string) []string {
	for i, val := range list {
		if val == txId {
			list[i] = list[len(list)-1]
			return list[:len(list)-1]
		}
	}
	return list
}

// clearSpendGroup removes EVERY record of the L7-01 spend group that the just-settled
// confirmedTxId belongs to — itself plus any RBF replacements sharing its reserved input
// set — plus the group object, atomically in this committed tx. This is the H2 guarantee
// (spec v2): a settle of ANY member clears the whole group, so a dangling sibling can never
// keep an "ms-"/"d-" record + list entry live with its inputs already deleted (which would
// inflate pendingMigrationState forever, re-arming the NN#3 freeze, and be uncleanable via
// confirmSpend's fail-closed input guard). inputIds is the confirmed record's input set (the
// group key). LAZY: with no re-drive the group object is absent → members == {confirmedTxId},
// byte-identical to the pre-L7-01 single-txid cleanup. The confirmed member's own settle
// already deleted the shared inputs + released reservations; this only deletes bookkeeping.
func (cs *ContractState) clearSpendGroup(confirmedTxId string, inputIds []uint16) {
	members := []string{confirmedTxId}
	gk := spendGroupKey(inputIds)
	if raw := sdk.StateGetObject(gk); raw != nil && *raw != "" {
		if g, err := UnmarshalSpendGroup([]byte(*raw)); err == nil {
			members = g.Members
			// Defensive: a settle must always clear its OWN records even if a corrupt
			// group object somehow omits the confirmed txid.
			present := false
			for _, m := range members {
				if m == confirmedTxId {
					present = true
					break
				}
			}
			if !present {
				members = append(members, confirmedTxId)
			}
		}
		sdk.StateDeleteObject(gk)
	}
	for _, m := range members {
		sdk.StateDeleteObject(constants.PendingUnmapPrefix + m)   // us-<m> (no-op if a sweep)
		sdk.StateDeleteObject(constants.MigrationSweepPrefix + m) // ms-<m> (no-op if an unmap)
		sdk.StateDeleteObject(constants.TxSpendsPrefix + m)       // d-<m>
		cs.TxSpendsList = removeTxid(cs.TxSpendsList, m)
		cs.MigrationSweeps = removeTxid(cs.MigrationSweeps, m)
	}
}

// ---------------------------------------------------------------------------
// Reserved-UTXO markers ("ru-"+id) — Guard 1 delete-at-confirm in-flight exclusion.
// A confirmed UTXO committed to an in-flight UNMAP stays in the registry until its tx
// confirms (settleUnmap); this per-UTXO marker keeps it out of BOTH the next unmap's
// selection and any migration sweep's selection meanwhile, so two in-flight spends can
// never double-select the same input. A marker (not a scanned list) so the migration path
// stays O(tranche candidates) — an unprivileged unmap flood can never gas-DoS rotation
// (BRK-1 council A-1 preserved). Set at unmap build, checked per selection candidate,
// deleted at settleUnmap paired with the UTXO delete.
// ---------------------------------------------------------------------------

func reservedUtxoKey(id uint16) string {
	return constants.ReservedUtxoPrefix + strconv.FormatUint(uint64(id), 10)
}

func reserveUtxo(id uint16) {
	sdk.StateSetObject(reservedUtxoKey(id), "1")
}

func unreserveUtxo(id uint16) {
	sdk.StateDeleteObject(reservedUtxoKey(id))
}

func isUtxoReserved(id uint16) bool {
	v := sdk.StateGetObject(reservedUtxoKey(id))
	return v != nil && *v != ""
}

// ---------------------------------------------------------------------------
// UTXO ID allocation with rollover and existence check
// ---------------------------------------------------------------------------

// allocateConfirmedId returns the next free slot in the confirmed pool (1024–65535).
// Wraps 65535 → 1024 and skips slots that already have state data.
func (cs *ContractState) allocateConfirmedId() (uint16, error) {
	startId := cs.ConfirmedNextId
	for {
		id := cs.ConfirmedNextId
		if cs.ConfirmedNextId == constants.UtxoMaxId {
			cs.ConfirmedNextId = constants.UtxoConfirmedPoolStart
		} else {
			cs.ConfirmedNextId++
		}
		existing := sdk.StateGetObject(getUtxoKey(id))
		if existing == nil || *existing == "" {
			return id, nil
		}
		if cs.ConfirmedNextId == startId {
			return 0, ce.NewContractError(ce.ErrStateAccess, "all confirmed UTXO slots are occupied")
		}
	}
}

// allocateUnconfirmedId returns the next free slot in the unconfirmed pool (0–1023).
// Wraps 1023 → 0 and skips slots that already have state data.
func (cs *ContractState) allocateUnconfirmedId() (uint16, error) {
	startId := cs.UnconfirmedNextId
	for {
		id := cs.UnconfirmedNextId
		if cs.UnconfirmedNextId >= constants.UtxoConfirmedPoolStart-1 {
			cs.UnconfirmedNextId = 0
		} else {
			cs.UnconfirmedNextId++
		}
		existing := sdk.StateGetObject(getUtxoKey(id))
		if existing == nil || *existing == "" {
			return id, nil
		}
		if cs.UnconfirmedNextId == startId {
			return 0, ce.NewContractError(ce.ErrStateAccess, "all unconfirmed UTXO slots are occupied")
		}
	}
}

// ---------------------------------------------------------------------------
// Account balance helpers (compact big-endian binary, unchanged)
// ---------------------------------------------------------------------------

func getAccBal(vscAcc string) int64 {
	s := sdk.StateGetObject(constants.BalancePrefix + vscAcc)
	if s == nil || *s == "" {
		return 0
	}
	var buf [8]byte
	copy(buf[8-len(*s):], *s)
	return int64(binary.BigEndian.Uint64(buf[:]))
}

func setAccBal(vscAcc string, newBal int64) {
	if newBal == 0 {
		sdk.StateDeleteObject(constants.BalancePrefix + vscAcc)
		return
	}
	v := uint64(newBal)
	n := (bits.Len64(v) + 7) / 8
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	sdk.StateSetObject(constants.BalancePrefix+vscAcc, string(buf[8-n:]))
}

func incAccBalance(vscAcc string, amount int64) error {
	bal := getAccBal(vscAcc)
	newBal, err := safeAdd64(bal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incrementing user balance")
	}
	setAccBal(vscAcc, newBal)
	return nil
}

func getAllowance(owner, spender string) int64 {
	s := sdk.StateGetObject(constants.AllowancePrefix + owner + constants.DirPathDelimiter + spender)
	if s == nil || *s == "" {
		return 0
	}
	var buf [8]byte
	copy(buf[8-len(*s):], *s)
	return int64(binary.BigEndian.Uint64(buf[:]))
}

func setAllowance(owner, spender string, amount int64) {
	key := constants.AllowancePrefix + owner + constants.DirPathDelimiter + spender
	if amount == 0 {
		sdk.StateDeleteObject(key)
		return
	}
	v := uint64(amount)
	n := (bits.Len64(v) + 7) / 8
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	sdk.StateSetObject(key, string(buf[8-n:]))
}

func StrPtr(s string) *string {
	return &s
}

// senderLabel returns the single sender address if all inputs share one address, or "many" otherwise.
func senderLabel(inputs []*wire.TxIn, network *chaincfg.Params) string {
	label := ""
	for _, in := range inputs {
		pkScript, err := txscript.ComputePkScript(in.SignatureScript, in.Witness)
		if err != nil {
			return "many"
		}
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript.Script(), network)
		if err != nil || len(addrs) == 0 {
			return "many"
		}
		addr := addrs[0].EncodeAddress()
		if label == "" {
			label = addr
		} else if label != addr {
			return "many"
		}
	}
	if label == "" {
		return "many"
	}
	return label
}

func createFeeLog(vscFee, btcFee int64) string {
	var b strings.Builder
	b.Grow(50)
	b.WriteString("fee")
	b.WriteString(constants.LogDelimiter)
	b.WriteString("m")
	b.WriteString(constants.LogKeyDelimiter)
	var buf [20]byte
	b.Write(strconv.AppendInt(buf[:0], vscFee, 10))
	b.WriteString(constants.LogDelimiter)
	b.WriteString("b")
	b.WriteString(constants.LogKeyDelimiter)
	b.Write(strconv.AppendInt(buf[:0], btcFee, 10))
	return b.String()
}

func createMapLog(from, to string, amount int64) string {
	var b strings.Builder
	b.Grow(128)
	b.WriteString("map")
	b.WriteString(constants.LogDelimiter)
	b.WriteString("t")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(to)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("f")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(from)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("a")
	b.WriteString(constants.LogKeyDelimiter)
	var buf [20]byte
	b.Write(strconv.AppendInt(buf[:0], amount, 10))
	return b.String()
}

func createTransferLog(from, to string, amount int64) string {
	var b strings.Builder
	b.Grow(128)
	b.WriteString("xfer")
	b.WriteString(constants.LogDelimiter)
	b.WriteString("f")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(from)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("t")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(to)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("a")
	b.WriteString(constants.LogKeyDelimiter)
	var buf [20]byte
	b.Write(strconv.AppendInt(buf[:0], amount, 10))
	return b.String()
}

func createUnmapLog(txId, from, to string, deducted, sent int64) string {
	var b strings.Builder
	b.Grow(128)
	b.WriteString("unmap")
	b.WriteString(constants.LogDelimiter)
	b.WriteString("id")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(txId)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("f")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(from)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("t")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(to)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("d")
	b.WriteString(constants.LogKeyDelimiter)
	var buf [20]byte
	b.Write(strconv.AppendInt(buf[:0], deducted, 10))
	b.WriteString(constants.LogDelimiter)
	b.WriteString("s")
	b.WriteString(constants.LogKeyDelimiter)
	b.Write(strconv.AppendInt(buf[:0], sent, 10))
	return b.String()
}

func safeAdd64(a, b int64) (int64, error) {
	if a > 0 && b > math.MaxInt64-a {
		return 0, errors.New("overflow detected")
	}
	if a < 0 && b < math.MinInt64-a {
		return 0, errors.New("underflow detected")
	}
	return a + b, nil
}

func safeMultiply64(a, b int64) (int64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	result := a * b
	if result/a != b {
		return 0, errors.New("overflow detected")
	}
	return result, nil
}

func safeSubtract64(a, b int64) (int64, error) {
	if b > 0 && a < math.MinInt64+b {
		return 0, errors.New("underflow detected")
	}
	if b < 0 && a > math.MaxInt64+b {
		return 0, errors.New("overflow detected")
	}
	return a - b, nil
}

// getUtxoKey returns the state key for a UTXO by its single-byte pool ID.
// Keys range from "utxo/0" to "utxo/ff".
func getUtxoKey(id uint16) string {
	return constants.UtxoPrefix + strconv.FormatUint(uint64(id), 16)
}

// ---------------------------------------------------------------------------
// Per-block observed tx list (34 bytes per entry: 32-byte txid + 2-byte vout BE)
// State key: "o-<blockHeight>"
// ---------------------------------------------------------------------------

const observedEntrySize = 34

func observedBlockKey(blockHeight uint32) string {
	return constants.ObservedBlockPrefix + strconv.FormatUint(uint64(blockHeight), 10)
}

// observedEntry is a compact 34-byte identifier for a single txid:vout pair.
type observedEntry [observedEntrySize]byte

func makeObservedEntry(txId string, vout uint32) (observedEntry, error) {
	var e observedEntry
	txIdBytes, err := hex.DecodeString(txId)
	if err != nil || len(txIdBytes) != 32 {
		return e, errors.New("invalid txid for observed entry")
	}
	copy(e[:32], txIdBytes)
	binary.BigEndian.PutUint16(e[32:], uint16(vout))
	return e, nil
}

// loadObservedList loads the packed observed entries for a block height.
func loadObservedList(blockHeight uint32) []observedEntry {
	raw := sdk.StateGetObject(observedBlockKey(blockHeight))
	if raw == nil || len(*raw) == 0 {
		return nil
	}
	data := []byte(*raw)
	if len(data)%observedEntrySize != 0 {
		return nil
	}
	out := make([]observedEntry, len(data)/observedEntrySize)
	for i := range out {
		copy(out[i][:], data[i*observedEntrySize:(i+1)*observedEntrySize])
	}
	return out
}

// isObserved checks whether the entry exists in the list.
func isObserved(list []observedEntry, entry observedEntry) bool {
	for _, e := range list {
		if e == entry {
			return true
		}
	}
	return false
}

// saveObservedList writes the packed observed entries for a block height.
func saveObservedList(blockHeight uint32, list []observedEntry) {
	buf := make([]byte, len(list)*observedEntrySize)
	for i, e := range list {
		copy(buf[i*observedEntrySize:], e[:])
	}
	sdk.StateSetObject(observedBlockKey(blockHeight), string(buf))
}

// markOutpointsObserved records (txId, vout) pairs in a block's observed list (council D-1/C-1,
// HIGH). The observed list is the single "already credited" ledger, but only `map` and
// `topUpFeeReserve` wrote it — the settle paths (settleUnmap change, settleMigrationSweep sweep)
// and the promotion loops turned on-chain outputs into confirmed vault UTXOs WITHOUT recording
// them, so a later topUpFeeReserve of the SAME outpoint (it pays the identical untagged vault
// address) could double-credit FeeSupply + double-index the outpoint (a phantom UTXO the
// Σ==Active+Fee assert cannot catch, since both sides inflate). Every path that creates a
// confirmed vault UTXO from an on-chain output must call this. Idempotent (skips entries already
// present) and bounded (one list load/save per call). Ordering is deterministic (append order =
// tx-output order at a deterministic call site), so the packed bytes match across nodes. The
// observed list is pruned in lock-step with its block header, so an entry lives exactly as long
// as the output stays SPV-provable — precisely the top-up attack window.
func markOutpointsObserved(blockHeight uint32, txId string, vouts []uint32) error {
	if len(vouts) == 0 {
		return nil
	}
	list := loadObservedList(blockHeight)
	changed := false
	for _, vout := range vouts {
		entry, err := makeObservedEntry(txId, vout)
		if err != nil {
			return ce.WrapContractError(ce.ErrInput, err, "error creating observed entry")
		}
		if isObserved(list, entry) {
			continue
		}
		list = append(list, entry)
		changed = true
	}
	if changed {
		saveObservedList(blockHeight, list)
	}
	return nil
}

// DeleteObservedList removes the observed tx list for a block height.
func DeleteObservedList(blockHeight uint32) {
	sdk.StateDeleteObject(observedBlockKey(blockHeight))
}

// DecodeCompressedPubKey decodes a hex string into a CompressedPubKey,
// validating that it is exactly 33 bytes with a 0x02 or 0x03 prefix.
func DecodeCompressedPubKey(hexStr string) (CompressedPubKey, error) {
	var key CompressedPubKey
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return key, err
	}
	if len(b) != 33 {
		return key, errors.New("invalid compressed public key length: expected 33 bytes")
	}
	if b[0] != 0x02 && b[0] != 0x03 {
		return key, errors.New("invalid compressed public key prefix: expected 0x02 or 0x03")
	}
	copy(key[:], b)
	return key, nil
}
