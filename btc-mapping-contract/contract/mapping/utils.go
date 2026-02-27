package mapping

import (
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
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
	if tag == nil || len(tag) > 0 {
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

// checks the balance and intents of the account to determine if the amount can be spent, then spends it
func checkAndDeductBalance(env sdk.Env, account string, amount int64) error {
	callerAddress := env.Caller.String()
	senderAddress := env.Sender.Address.String()
	bal, err := getAccBal(account)
	if err != nil {
		return ce.NewContractError(ce.ErrStateAccess, "could not fetch balance for account ("+account+")")
	}
	if bal < amount {
		return ce.NewContractError(
			ce.ErrBalance,
			"sender balance "+strconv.FormatInt(bal, 10)+" insufficient needs "+strconv.FormatInt(amount, 10),
		)
	}
	switch account {
	case senderAddress:
		intentAmount := int64(0)
		//check sender's intents
		for _, intent := range env.SenderIntents {
			if intent.Type != intentTransferType {
				continue
			}
			if contractId, ok := intent.Args[intentContractIdKey]; ok && contractId == env.ContractId {
				// sdk.Log("found intent for this contract: " + fmt.Sprintf("%v", intent))
				if amount, ok := intent.Args[intentLimitKey]; ok {
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

		// write deducted balance and track spend
		newBal, err := safeSubtract64(bal, amount)
		if err != nil {
			return ce.WrapContractError(ce.ErrArithmetic, err, "error incremting user balance")
		}
		setAccBal(account, newBal)
		setAccExpenditure(account, expenditure+amount)
		return nil
	case callerAddress:
		intentAmount := int64(0)
		//check caller's intents
		for _, intent := range env.CallerIntents {
			if intent.Type != intentTransferType {
				continue
			}
			if contractId, ok := intent.Args[intentContractIdKey]; ok && contractId == env.ContractId {
				// sdk.Log("found intent for this contract: " + intent.Args[intentLimitKey] + " " + intent.Args["token"])
				if amount, ok := intent.Args[intentLimitKey]; ok {
					clean := strings.Replace(amount, ".", "", 1)
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
		// write deducted balance and track spend
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

func packUtxo(internalId uint32, amount int64, confirmed uint8) [3]int64 {
	return [3]int64{int64(internalId), amount, int64(confirmed)}
}

func unpackUtxo(utxo [3]int64) (uint32, int64, uint8) {
	return uint32(utxo[0]), utxo[1], uint8(utxo[2])
}

func getAccBal(vscAcc string) (int64, error) {
	balString := sdk.StateGetObject(balancePrefix + vscAcc)
	if *balString == "" {
		return 0, nil
	}
	bal, err := strconv.ParseInt(*balString, 10, 64)
	if err != nil {
		return 0, err
	}
	return bal, nil
}

// sets account balance to number (in base 10)
func setAccBal(vscAcc string, newBal int64) {
	sdk.StateSetObject(balancePrefix+vscAcc, strconv.FormatInt(newBal, 10))
}

func incAccBalance(vscAcc string, amount int64) error {
	bal, err := getAccBal(vscAcc)
	if err != nil {
		return err
	}
	newBal, err := safeAdd64(bal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incremting user balance")
	}
	setAccBal(vscAcc, newBal)
	return nil
}

// gets the amount spent so far in this transaction
func getAccExpenditure(contractId, vscAcc string) (int64, error) {
	balString := sdk.EphemStateGetObject(contractId, intentExpenditurePrefix+vscAcc)
	if *balString == "" {
		return 0, nil
	}
	bal, err := strconv.ParseInt(*balString, 10, 64)
	if err != nil {
		return 0, err
	}
	return bal, nil
}

// sets the amount spent so far in this transaction
func setAccExpenditure(vscAcc string, newBal int64) {
	sdk.EphemStateSetObject(balancePrefix+vscAcc, strconv.FormatInt(newBal, 10))
}

// func deduct(vscAcc string, amount, balance, expenditure int64) {
// 	setAccBal(vscAcc, balance-amount)
// 	setAccExpenditure(vscAcc, expenditure+amount)
// }

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
	return utxoPrefix + strconv.FormatUint(uint64(id), 16)
}

func joinIdVout(utxo Utxo) string {
	return utxo.TxId + ":" + strconv.FormatUint(uint64(utxo.Vout), 10)
}
