package sdk

import (
	"encoding/hex"
	"strconv"

	tinyjson "github.com/CosmWasm/tinyjson"
)

// Aborts the contract execution
func Abort(msg string) {
	ln := int32(0)
	abort(&msg, nil, &ln, &ln)
	panic(msg)
}

// Reverts the transaction and abort execution in the same way as Abort().
func Revert(msg string, symbol string) {
	revert(&msg, &symbol)
}

// Set a value by key in the contract state
func StateSetObject(key string, value string) {
	stateSetObject(&key, &value)
}

// Get a value by key from the contract state
func StateGetObject(key string) *string {
	return stateGetObject(&key)
}

// Delete or unset a value by key in the contract state
func StateDeleteObject(key string) {
	stateDeleteObject(&key)
}

// Set a value by key in the ephemeral contract state
func EphemStateSetObject(key string, value string) {
	ephemStateSetObject(&key, &value)
}

// Get a value by key from the ephemeral contract state
func EphemStateGetObject(contractId string, key string) *string {
	return ephemStateGetObject(&contractId, &key)
}

// Delete or unset a value by key in the ephemeral contract state
func EphemStateDeleteObject(key string) {
	ephemStateDeleteObject(&key)
}

// Get current execution environment variables
func GetEnv() Env {
	envStr := *getEnv(nil)
	env := Env{}
	tinyjson.Unmarshal([]byte(envStr), &env)
	envMap := EnvMap{}
	tinyjson.Unmarshal([]byte(envStr), &envMap)

	requiredAuths := make([]Address, 0)
	if auths, ok := envMap["msg.required_auths"].([]interface{}); ok {
		for _, auth := range auths {
			if addr, ok := auth.(string); ok {
				requiredAuths = append(requiredAuths, Address(addr))
			}
		}
	}
	requiredPostingAuths := make([]Address, 0)
	if auths, ok := envMap["msg.required_posting_auths"].([]interface{}); ok {
		for _, auth := range auths {
			if addr, ok := auth.(string); ok {
				requiredPostingAuths = append(requiredPostingAuths, Address(addr))
			}
		}
	}

	senderAddr := ""
	if s, ok := envMap["msg.sender"].(string); ok {
		senderAddr = s
	}
	if senderAddr == "" {
		Abort("msg.sender is missing from environment")
	}

	env.Sender = Sender{
		Address:              Address(senderAddr),
		RequiredAuths:        requiredAuths,
		RequiredPostingAuths: requiredPostingAuths,
	}
	return env
}

// Get current execution environment variables as json string
func GetEnvStr() string {
	return *getEnv(nil)
}

// Get current execution environment variable by a key
func GetEnvKey(key string) *string {
	return getEnvKey(&key)
}

// VerifyAddress asks the runtime to validate an address and returns its type.
// Returns one of: "user:hive", "user:evm", "key", "contract", "system", "unknown".
func VerifyAddress(addr string) string {
	return *verifyAddress(&addr)
}

// Get balance of an account
func GetBalance(address Address, asset Asset) int64 {
	addr := address.String()
	as := asset.String()
	balStr := *getBalance(&addr, &as)
	bal, err := strconv.ParseInt(balStr, 10, 64)
	if err != nil {
		panic(err)
	}
	return bal
}

// Transfer assets from caller account to the contract up to the limit specified in `intents`. The transaction must be signed using active authority for Hive accounts.
func HiveDraw(amount int64, asset Asset) {
	amt := strconv.FormatInt(amount, 10)
	as := asset.String()
	hiveDraw(&amt, &as)
}

func HiveDrawFrom(from Address, amount int64, asset Asset) {
	frm := from.String()
	amt := strconv.FormatInt(amount, 10)
	as := asset.String()
	hiveDrawFrom(&frm, &amt, &as)
}

// Transfer assets from the contract to another account.
func HiveTransfer(to Address, amount int64, asset Asset) {
	toaddr := to.String()
	amt := strconv.FormatInt(amount, 10)
	as := asset.String()
	hiveTransfer(&toaddr, &amt, &as)
}

// Unmap assets from the contract to a specified Hive account.
func HiveWithdraw(to Address, amount int64, asset Asset) {
	toaddr := to.String()
	amt := strconv.FormatInt(amount, 10)
	as := asset.String()
	hiveWithdraw(&toaddr, &amt, &as)
}

// Get a value by key from the contract state of another contract
func ContractStateGet(contractId string, key string) *string {
	return contractRead(&contractId, &key)
}

// Call another contract
func ContractCall(contractId string, method string, payload string, options *ContractCallOptions) *string {
	optStr := ""
	if options != nil {
		optByte, err := tinyjson.Marshal(options)
		if err != nil {
			Revert("could not serialize options", "sdk_error")
		}
		optStr = string(optByte)
	}
	return contractCall(&contractId, &method, &payload, &optStr)
}

// CryptoBlsVerifyAggregate verifies a quorum-aggregated BLS12-381 signature
// against a list of pubkeys all signing the same message. Wraps the
// crypto.bls_verify_aggregate host function added to vsc-node in
// go-vsc-node modules/wasm/sdk/sdk.go (workstream 4a of the Dash
// IS-login feature).
//
// pubkeysConcat: hex-encoded concatenation of N 48-byte compressed G1
//
//	pubkeys. Length MUST be a multiple of 96 hex chars,
//	at least 1 pubkey, at most 256 (the host enforces).
//
// msgHex:        arbitrary-length message digest (typically a 32-byte
//
//	SHA-256 hash including the dash-is-lock-v1\0 domain
//	prefix per the spec §5.6 canonical signing message).
//
// aggSigHex:     hex-encoded 96-byte compressed G2 aggregate signature.
//
// Returns "true" / "false" — distinct from nil which would indicate a
// host-level error (malformed inputs). Use VerifyBlsAggregate for a
// bool-returning convenience wrapper.
func CryptoBlsVerifyAggregate(pubkeysConcat string, msgHex string, aggSigHex string) *string {
	return cryptoBlsVerifyAggregate(&pubkeysConcat, &msgHex, &aggSigHex)
}

// VerifyBlsAggregate is the bool-returning convenience wrapper around
// CryptoBlsVerifyAggregate. Returns false on malformed inputs (so calling
// contracts can fail-closed on bad data).
func VerifyBlsAggregate(pubkeysConcat string, msgHex string, aggSigHex string) bool {
	r := CryptoBlsVerifyAggregate(pubkeysConcat, msgHex, aggSigHex)
	if r == nil {
		return false
	}
	return *r == "true"
}

// CryptoBlsVerify verifies a single-pubkey BLS12-381 signature. Wraps
// the crypto.bls_verify host function. Used by the dash-mapping-contract
// for per-validator Proof-of-Possession at validator-set registration
// (audit R3-001 — closes the rogue-key aggregate-forgery hole).
//
// pubkeyHex:  hex-encoded 48-byte compressed G1 pubkey (96 chars).
// msgHex:     hex-encoded arbitrary-length message bytes.
// sigHex:     hex-encoded 96-byte compressed G2 signature.
//
// Returns "true" / "false" — distinct from nil for host-level error.
func CryptoBlsVerify(pubkeyHex string, msgHex string, sigHex string) *string {
	return cryptoBlsVerify(&pubkeyHex, &msgHex, &sigHex)
}

// VerifyBls is the bool-returning convenience wrapper around
// CryptoBlsVerify. Returns false on malformed inputs.
func VerifyBls(pubkeyHex string, msgHex string, sigHex string) bool {
	r := CryptoBlsVerify(pubkeyHex, msgHex, sigHex)
	if r == nil {
		return false
	}
	return *r == "true"
}

func TssCreateKey(keyId string, algo string, epochs uint64) string {
	if algo != "ecdsa" && algo != "eddsa" {
		Abort("algo must be ecdsa or eddsa")
	}
	epochsStr := strconv.FormatUint(epochs, 10)
	return *tssCreateKey(&keyId, &algo, &epochsStr)
}

func TssRenewKey(keyId string, additionalEpochs uint64) string {
	epochsStr := strconv.FormatUint(additionalEpochs, 10)
	return *tssRenewKey(&keyId, &epochsStr)
}

func TssGetKey(keyId string) string {
	return *tssGetKey(&keyId)
}

func TssSignKey(keyId string, bytes []byte) {
	byteStr := hex.EncodeToString(bytes)

	tssSignKey(&keyId, &byteStr)
}
