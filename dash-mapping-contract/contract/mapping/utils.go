package mapping

import (
	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
	"dash-mapping-contract/sdk"
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
	primaryPubKeyHex string, backupPubKeyHex string, tag []byte, network *chaincfg.Params,
) (string, []byte, error) {
	primaryPubKeyBytes, err := hex.DecodeString(primaryPubKeyHex)
	if err != nil {
		return "", nil, err
	}

	if backupPubKeyHex == "" {
		return createSimpleP2WSHAddress(primaryPubKeyBytes, tag, network)
	}

	backupPubKeyBytes, err := hex.DecodeString(backupPubKeyHex)
	if err != nil {
		return "", nil, err
	}

	csvBlocks := backupCSVBlocks

	if network.Net != chaincfg.MainNetParams.Net {
		csvBlocks = 2
	}

	scriptBuilder := txscript.NewScriptBuilder()

	// start if
	scriptBuilder.AddOp(txscript.OP_IF)

	// primary spending path
	// uses OP_CHECKSIG instead of OP_CHECKSIGVERIFY for tags of length 0
	// because an empty tag will leave the stack empty after verificaiton
	// and the tx will fail
	scriptBuilder.AddData(primaryPubKeyBytes)
	if len(tag) > 0 {
		scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY)
		scriptBuilder.AddData(tag)
	} else {
		scriptBuilder.AddOp(txscript.OP_CHECKSIG)
	}

	// else: backup path
	scriptBuilder.AddOp(txscript.OP_ELSE)

	// CSV timelock check
	scriptBuilder.AddInt64(int64(csvBlocks))
	scriptBuilder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	scriptBuilder.AddOp(txscript.OP_DROP) // CSV leaves value on stack, need to drop it

	// backup key signature check
	scriptBuilder.AddData(backupPubKeyBytes)
	scriptBuilder.AddOp(txscript.OP_CHECKSIG)

	// end if
	scriptBuilder.AddOp(txscript.OP_ENDIF)

	script, err := scriptBuilder.Script()
	if err != nil {
		return "", nil, err
	}

	// Create P2WSH address
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
	// uses OP_CHECKSIG instead of OP_CHECKSIGVERIFY for tags of length 0
	// because an empty tag will leave the stack empty after verificaiton
	// and the tx will fail
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

	var address string
	witnessProgram := sha256.Sum256(script)
	addressWitnessScriptHash, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], network)
	if err != nil {
		return "", nil, err
	}
	address = addressWitnessScriptHash.EncodeAddress()

	return address, script, nil
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

func packUtxo(internalId uint32, amount int64, confirmed uint8) [3]int64 {
	return [3]int64{int64(internalId), amount, int64(confirmed)}
}

func unpackUtxo(utxo [3]int64) (uint32, int64, uint8) {
	return uint32(utxo[0]), utxo[1], uint8(utxo[2])
}

func getAccBal(vscAcc string) int64 {
	s := sdk.StateGetObject(BalancePrefix + vscAcc)
	if s == nil || *s == "" {
		return 0
	}
	var buf [8]byte
	copy(buf[8-len(*s):], *s)
	return int64(binary.BigEndian.Uint64(buf[:]))
}

func setAccBal(vscAcc string, newBal int64) {
	if newBal == 0 {
		sdk.StateDeleteObject(BalancePrefix + vscAcc)
		return
	}
	v := uint64(newBal)
	n := (bits.Len64(v) + 7) / 8
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	sdk.StateSetObject(BalancePrefix+vscAcc, string(buf[8-n:]))
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

	b.WriteString("deposit")
	b.WriteString(logDelimiter)

	b.WriteString("t")
	b.WriteString(logKeyDelimiter)
	b.WriteString(d.to)
	b.WriteString(logDelimiter)

	b.WriteString("f")
	b.WriteString(logKeyDelimiter)
	for i, s := range d.from {
		if i > 0 {
			b.WriteString(logArrayDelimiter)
		}
		b.WriteString(s)
	}
	b.WriteString(logDelimiter)

	b.WriteString("a")
	b.WriteString(logKeyDelimiter)

	var buf [20]byte
	b.Write(strconv.AppendInt(buf[:0], d.amount, 10))

	return b.String()
}

func createFeeLog(vscFee, btcFee int64) string {
	var b strings.Builder

	// 1. Pre-allocate capacity.
	// "fee|vsc:int64|btc:int64" is usually < 64 bytes.
	b.Grow(64)

	// 2. Header
	b.WriteString("fee")
	b.WriteString(logDelimiter)

	// 3. VSC Fee
	b.WriteString("magi")
	b.WriteString(logKeyDelimiter)

	// Temporary stack buffer for integer conversion (max 20 digits for int64)
	var buf [20]byte
	b.Write(strconv.AppendInt(buf[:0], vscFee, 10))
	b.WriteString(logDelimiter)

	// 4. BTC Fee
	b.WriteString("dash")
	b.WriteString(logKeyDelimiter)
	b.Write(strconv.AppendInt(buf[:0], btcFee, 10))

	// 5. Final String Conversion (1 allocation)
	return b.String()
}

func createUnmapLog(txId string) string {
	var b strings.Builder
	b.Grow(71)
	b.WriteString("unm")
	b.WriteString(logDelimiter)
	b.WriteString("id")
	b.WriteString(logKeyDelimiter)
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

func getUtxoKey(id uint32) string {
	return UtxoPrefix + strconv.FormatUint(uint64(id), 16)
}

func getObservedKey(utxo Utxo) string {
	return ObservedPrefix + utxo.TxId + ":" + strconv.FormatUint(uint64(utxo.Vout), 10)
}
