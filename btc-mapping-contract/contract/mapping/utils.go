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
)

func createP2WSHAddressWithBackup(
	primaryPubKey CompressedPubKey, backupPubKey CompressedPubKey, tag []byte, network *chaincfg.Params,
) (string, []byte, error) {
	csvBlocks := constants.BackupCSVBlocks

	if network.Net != chaincfg.MainNetParams.Net {
		csvBlocks = 2
	}

	scriptBuilder := txscript.NewScriptBuilder()

	// start if
	scriptBuilder.AddOp(txscript.OP_IF)

	// primary spending path
	scriptBuilder.AddData(primaryPubKey[:])
	if tag == nil || len(tag) > 0 {
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

func buildIntentError(remaining int64, amount int64, address string) error {
	return ce.NewContractError(
		ce.ErrIntent,
		"insufficient intent ("+
			strconv.FormatInt(remaining, 10)+
			") remaining to cover spend ("+
			strconv.FormatInt(amount, 10)+
			") for "+
			address,
	)
}

func checkAndDeductBalance(env sdk.Env, account string, amount int64) error {
	callerAddress := env.Caller.String()
	senderAddress := env.Sender.Address.String()
	bal := getAccBal(account)
	if bal < amount {
		return ce.NewContractError(
			ce.ErrBalance,
			"account ["+account+"] balance "+strconv.FormatInt(bal, 10)+
				" insufficient needs "+strconv.FormatInt(amount, 10),
		)
	}
	switch account {
	case senderAddress:
		intentAmount := int64(0)
		for _, intent := range env.SenderIntents {
			if intent.Type != constants.IntentTransferType {
				continue
			}
			if contractId, ok := intent.Args[constants.IntentContractIdKey]; ok && contractId == env.ContractId {
				if amount, ok := intent.Args[constants.IntentLimitKey]; ok {
					var err error
					intentAmount, err = strconv.ParseInt(amount, 10, 64)
					if err != nil {
						return ce.WrapContractError(ce.ErrIntent, err, "invalid intent amount")
					}
					break
				}
			}
		}

		expenditure, err := getAccExpenditure(env.ContractId, senderAddress)
		if err != nil {
			return ce.WrapContractError(ce.ErrStateAccess, err, "error fetching previous token expenditure")
		}
		remaining := intentAmount - expenditure
		if remaining < amount {
			return buildIntentError(remaining, amount, senderAddress)
		}

		newBal, err := safeSubtract64(bal, amount)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "error incremting user balance")
		}
		setAccBal(account, newBal)
		setAccExpenditure(account, expenditure+amount)
		return nil
	case callerAddress:
		intentAmount := int64(0)
		for _, intent := range env.CallerIntents {
			if intent.Type != constants.IntentTransferType {
				continue
			}
			if contractId, ok := intent.Args[constants.IntentContractIdKey]; ok && contractId == env.ContractId {
				if amount, ok := intent.Args[constants.IntentLimitKey]; ok {
					clean := strings.Replace(amount, ".", "", 1)
					var err error
					intentAmount, err = strconv.ParseInt(clean, 10, 64)
					if err != nil {
						return ce.NewContractError(ce.ErrIntent, "invalid intent amount")
					}
				}
			}
		}

		if intentAmount < amount {
			return buildIntentError(intentAmount, amount, account)
		}
		newBal, err := safeSubtract64(bal, amount)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "error incremting user balance")
		}
		setAccBal(account, newBal)
		return nil
	default:
		return ce.NewContractError(ce.ErrIntent, account+" is not the sender or caller")
	}
}

// ---------------------------------------------------------------------------
// UTXO registry binary encoding (9 bytes/entry: 1 byte ID + 8 bytes amount BE)
// ID 0–63 = unconfirmed pool; ID 64–255 = confirmed pool.
// ---------------------------------------------------------------------------

func MarshalUtxoRegistry(r UtxoRegistry) []byte {
	buf := make([]byte, len(r)*9)
	for i, e := range r {
		buf[i*9] = e.Id
		binary.BigEndian.PutUint64(buf[i*9+1:], uint64(e.Amount))
	}
	return buf
}

func UnmarshalUtxoRegistry(data []byte) (UtxoRegistry, error) {
	if len(data)%9 != 0 {
		return nil, errors.New("invalid utxo registry: length not a multiple of 9")
	}
	out := make(UtxoRegistry, len(data)/9)
	for i := range out {
		out[i].Id = data[i*9]
		out[i].Amount = int64(binary.BigEndian.Uint64(data[i*9+1:]))
	}
	return out, nil
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
// ---------------------------------------------------------------------------

func MarshalUtxo(u *Utxo) []byte {
	txIdBytes, _ := hex.DecodeString(u.TxId)
	total := 32 + 4 + 8 + 1 + len(u.PkScript) + 1 + len(u.Tag)
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
	return u, nil
}

func loadUtxo(id uint8) (*Utxo, error) {
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

func saveUtxo(id uint8, u *Utxo) {
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
		decoded, _ := hex.DecodeString(txId)
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
// UTXO ID allocation with rollover and existence check
// ---------------------------------------------------------------------------

// allocateConfirmedId returns the next free slot in the confirmed pool (64–255).
// Wraps 255 → 64 and skips slots that already have state data.
func (cs *ContractState) allocateConfirmedId() (uint8, error) {
	startId := cs.ConfirmedNextId
	for {
		id := cs.ConfirmedNextId
		if cs.ConfirmedNextId == 255 {
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

// allocateUnconfirmedId returns the next free slot in the unconfirmed pool (0–63).
// Wraps 63 → 0 and skips slots that already have state data.
func (cs *ContractState) allocateUnconfirmedId() (uint8, error) {
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
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incremting user balance")
	}
	setAccBal(vscAcc, newBal)
	return nil
}

func getAccExpenditure(contractId, vscAcc string) (int64, error) {
	balString := sdk.EphemStateGetObject(contractId, constants.IntentExpenditurePrefix+vscAcc)
	if *balString == "" {
		return 0, nil
	}
	bal, err := strconv.ParseInt(*balString, 10, 64)
	if err != nil {
		return 0, err
	}
	return bal, nil
}

func setAccExpenditure(vscAcc string, newBal int64) {
	sdk.EphemStateSetObject(constants.BalancePrefix+vscAcc, strconv.FormatInt(newBal, 10))
}

func (cs *ContractState) getNetwork(s string) (Network, error) {
	networkName := NetworkName(strings.ToLower(s))
	network, ok := cs.NetworkOptions[networkName]
	if ok {
		return network, nil
	}
	return nil, ce.NewContractError(ce.ErrInput, "invalid network \""+s+"\"")
}

func StrPtr(s string) *string {
	return &s
}

func createDepositLog(d Deposit) string {
	var b strings.Builder
	b.Grow(128)
	b.WriteString("dep")
	b.WriteString(constants.LogDelimiter)
	b.WriteString("t")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(d.to)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("f")
	b.WriteString(constants.LogKeyDelimiter)
	for i, s := range d.from {
		if i > 0 {
			b.WriteString(constants.LogArrayDelimiter)
		}
		b.WriteString(s)
	}
	b.WriteString(constants.LogDelimiter)
	b.WriteString("a")
	b.WriteString(constants.LogKeyDelimiter)
	var buf [20]byte
	b.Write(strconv.AppendInt(buf[:0], d.amount, 10))
	return b.String()
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

func createUnmapLog(txId string) string {
	var b strings.Builder
	b.Grow(71)
	b.WriteString("unm")
	b.WriteString(constants.LogDelimiter)
	b.WriteString("id")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(txId)
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
func getUtxoKey(id uint8) string {
	return constants.UtxoPrefix + strconv.FormatUint(uint64(id), 16)
}

func getObservedKey(utxo Utxo) string {
	return constants.ObservedPrefix + utxo.TxId + ":" + strconv.FormatUint(uint64(utxo.Vout), 10)
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
