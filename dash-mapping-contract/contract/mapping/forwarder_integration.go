// Workstream 5 — Dash IS-login forwarder integration for dash-mapping-contract.
//
// Implements the fast-path `mapInstantSendV2` action per spec §5.2.2-§5.2.7.
// The slow-path `Map` action (oracle-attested, block-proof-based) is unchanged
// and lives in handlers.go.
//
// Cross-references:
//   - Spec §5.2.2 lazy-attestation auth model (BLS quorum from Magi validators)
//   - Spec §5.2.3 pay-and-call atomicity sequence
//   - Spec §5.2.4 amount-matching rules
//   - Spec §5.2.5 strict same-address-all-inputs DashDID rule
//   - Spec §5.2.6 RC accounting via internal HBD ledger
//   - Spec §5.2.7 rate limits + allow-list governance
//   - dash-forwarder-contract/contract/forwarder/forwarder.go (downstream dispatch)
package mapping

import (
	"bytes"
	"crypto/sha256"
	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
	"dash-mapping-contract/sdk"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// ----- payload types -----

// MapInstantSendV2Params is the new payload shape for the lazy-attestation
// fast path. Carries the validator attestations bundle + the instruction
// string the user paid for + the epoch the attestations were collected at.
//
//tinyjson:json
type MapInstantSendV2Params struct {
	RawTxHex     string                 `json:"raw_tx_hex"`
	Instruction  string                 `json:"instruction"`
	Epoch        uint64                 `json:"epoch"`
	Attestations []ValidatorAttestation `json:"attestations"`
	// ChainId disambiguates testnet/mainnet/etc in the canonical signed
	// message. Reads from sysconfig (system contract) — set in the params
	// rather than read in-contract so the test framework has an explicit
	// hook. Must match NetworkMode's expected vsc network id.
	ChainId string `json:"chain_id"`
}

// ValidatorAttestation is one signed entry from a Magi validator's
// IsLockAttestationResponse. The contract verifies these as a BLS
// aggregate against the validator set at the attestation epoch.
//
//tinyjson:json
type ValidatorAttestation struct {
	// ValidatorDID is the did:key:z... ref to the validator's BLS pubkey.
	// Looked up against the at-epoch validator set in state.
	ValidatorDID string `json:"validator_did"`
	// PubkeyHex is the validator's 48-byte BLS pubkey, hex-encoded.
	// Passed in the params (rather than read from validator-set state)
	// because the contract aggregates these locally before calling
	// crypto.bls_verify_aggregate. The validator-set state lookup
	// confirms each pubkey is registered for the given epoch.
	PubkeyHex string `json:"pubkey_hex"`
	// BlsSigHex is the 96-byte BLS signature over the canonical
	// signing message, hex-encoded. Each validator signs the SAME
	// message; the contract aggregates the sigs off-chain (in the IS
	// service) before submission.
	BlsSigHex string `json:"sig_hex"`
}

// AggregatedSigHex is the SINGLE aggregate sig produced off-chain by the
// IS service via bls.Aggregate(individual sigs). Stored in params
// separately so the contract doesn't need to do the aggregation
// (it would need additional host functions for that). The individual
// sigs in ValidatorAttestation.BlsSigHex are kept for debuggability
// and audit but are NOT individually verified at runtime — the
// aggregate is the load-bearing check.
//
//tinyjson:json
type AggregatedSig struct {
	AggSigHex string `json:"agg_sig_hex"`
}

// MapInstantSendV2ParamsFull pairs the body with the aggregate signature.
// In production these will likely be folded into one struct via tinyjson
// regeneration; for the scaffold we keep them separate for clarity.
//
//tinyjson:json
type MapInstantSendV2ParamsFull struct {
	Body MapInstantSendV2Params `json:"body"`
	Agg  AggregatedSig          `json:"agg"`
}

// ----- ParsedInstruction -----

// ParsedInstruction is the structured form of an op=... instruction.
// Mirrors dash-forwarder-contract's parsed shape exactly.
type ParsedInstruction struct {
	Op          string
	Target      string
	Method      string
	ArgsB64     string
	Sid         string
	AmountDuffs int64
}

// ParseInstructionV2 unpacks the canonical instruction string per §5.2.1
// grammar. Public for use by both this package and dash-forwarder-contract.
func ParseInstructionV2(instruction string) (ParsedInstruction, error) {
	var out ParsedInstruction
	if instruction == "" {
		return out, ce.NewContractError(ce.ErrInput, "instruction empty")
	}
	fields := strings.Split(instruction, constants.InstructionFieldDelimiter)
	for _, f := range fields {
		idx := strings.Index(f, constants.InstructionKVDelimiter)
		if idx < 0 {
			return out, ce.NewContractError(ce.ErrInput, "instruction field missing delimiter: "+f)
		}
		key := f[:idx]
		val := f[idx+1:]
		switch key {
		case constants.InstructionOpKey:
			out.Op = val
		case constants.InstructionContractKey:
			out.Target = val
		case constants.InstructionMethodKey:
			out.Method = val
		case constants.InstructionArgsKey:
			out.ArgsB64 = val
		case constants.InstructionSidKey:
			out.Sid = val
		case constants.InstructionAmountKey:
			n, perr := atoi64(val)
			if perr != nil {
				return out, ce.NewContractError(ce.ErrInput, "invalid amount: "+val)
			}
			out.AmountDuffs = n
		}
	}
	if out.Op == "" {
		return out, ce.NewContractError(ce.ErrInput, "instruction missing op=")
	}
	if out.Op == constants.OpCallValue {
		if out.Target == "" || out.Method == "" {
			return out, ce.NewContractError(ce.ErrInput, "op=call requires contract= and method=")
		}
	}
	if out.Sid == "" {
		return out, ce.NewContractError(ce.ErrInput, "instruction missing sid=")
	}
	return out, nil
}

// ----- DashDID resolution from raw tx -----

// dashISLockDomainPrefix is the domain-separation tag for IS-lock
// attestation signing. MUST match lib/dids/dash.go's DashISLockDomainPrefix
// and modules/islock-attestation/attestation.go's canonical message format.
const dashISLockDomainPrefix = "dash-is-lock-v1\x00"

// ResolveSenderDashDID parses raw Dash tx bytes (hex), enforces the strict
// "all inputs spend from the same address" rule (§5.2.5), and returns the
// DashDID for that address. Returns an error on multi-address inputs,
// unparseable scripts, or unsupported address types.
//
// The DashDID format is `did:pkh:bip122:<chain-genesis-32hex>:<addr>`.
// Caller supplies the chain genesis hex (depends on network — mainnet vs
// testnet). MUST match lib/dids/dash.go's prefix constants.
func ResolveSenderDashDID(
	rawTxHex string,
	dashGenesisCAIP2Hex string,
	netParams *chaincfg.Params,
) (string, error) {
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return "", ce.NewContractError(ce.ErrInput, "raw tx not hex: "+err.Error())
	}
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(rawTxBytes)); err != nil {
		return "", ce.NewContractError(ce.ErrInput, "raw tx parse: "+err.Error())
	}
	return resolveDashDIDFromTxInputs(&msgTx, dashGenesisCAIP2Hex, netParams)
}

// resolveDashDIDFromTxInputs walks the inputs and enforces strict-same-
// address. Caller has already deserialised the tx. Address recovery from
// witness/scriptSig uses btcutil's ComputePkScript + ExtractPkScriptAddrs,
// same pattern used by senderLabel() in utils.go.
func resolveDashDIDFromTxInputs(tx *wire.MsgTx, dashGenesisCAIP2Hex string, netParams *chaincfg.Params) (string, error) {
	if len(tx.TxIn) == 0 {
		return "", ce.NewContractError(ce.ErrInput, "tx has no inputs")
	}
	var sender string
	for i, in := range tx.TxIn {
		pkScript, err := txscript.ComputePkScript(in.SignatureScript, in.Witness)
		if err != nil {
			return "", ce.NewContractError(ce.ErrInput,
				"input "+strconv.Itoa(i)+": cannot compute pkScript")
		}
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript.Script(), netParams)
		if err != nil || len(addrs) == 0 {
			return "", ce.NewContractError(ce.ErrInput,
				"input "+strconv.Itoa(i)+": cannot extract address")
		}
		addr := addrs[0].EncodeAddress()
		if sender == "" {
			sender = addr
		} else if sender != addr {
			// Strict rule per §5.2.5: any divergence rejects.
			return "", ce.NewContractError(ce.ErrInput,
				"multi-address inputs: "+sender+" vs "+addr+" (§5.2.5 strict rule)")
		}
	}
	if sender == "" {
		return "", ce.NewContractError(ce.ErrInput, "could not resolve sender address")
	}
	return "did:pkh:bip122:" + dashGenesisCAIP2Hex + ":" + sender, nil
}

// ----- Outputs lookup -----

// FindOutputAmount finds the output amount paid to the given address in
// the raw tx. Returns 0 if not present. Used by HandleMapInstantSendV2
// to verify the user actually paid to D and to derive the actualISAmount
// for amount-matching.
func FindOutputAmount(rawTxHex, targetAddress string, netParams *chaincfg.Params) (int64, error) {
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return 0, ce.NewContractError(ce.ErrInput, "raw tx not hex")
	}
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(rawTxBytes)); err != nil {
		return 0, ce.NewContractError(ce.ErrInput, "raw tx parse: "+err.Error())
	}
	var total int64
	for _, out := range msgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, netParams)
		if err != nil || len(addrs) == 0 {
			continue
		}
		if addrs[0].EncodeAddress() == targetAddress {
			total += out.Value
		}
	}
	return total, nil
}

// ----- BLS canonical signing message -----

// CanonicalAttestationMessage builds the message digest validators sign
// for IS-lock attestations. Mirrors go-vsc-node/modules/islock-attestation
// /attestation.go's CanonicalSigningMessage. MUST stay in lockstep —
// any drift breaks the entire fast-path verification.
//
// Format:
//
//	H( "dash-is-lock-v1\0" || chainId || epoch_be8 || txid || rawTxHash || instructionHash )
//
// Where txid, rawTxHash, and instructionHash are the raw 32-byte hashes.
func CanonicalAttestationMessage(
	chainId string,
	epoch uint64,
	rawTxHex, instruction string,
) ([]byte, error) {
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return nil, ce.NewContractError(ce.ErrInput, "raw tx not hex")
	}
	// Dash txid is sha256d(rawTx) (Bitcoin convention).
	first := sha256.Sum256(rawTxBytes)
	txidRaw := sha256.Sum256(first[:])
	// Note: Dash displays txids in little-endian reverse; the raw bytes
	// here match what validators signed (they use the same big-endian
	// of sha256d as we do).
	rawTxHashRaw := sha256.Sum256(rawTxBytes)
	instrHashRaw := sha256.Sum256([]byte(instruction))

	var buf bytes.Buffer
	buf.WriteString(dashISLockDomainPrefix)
	buf.WriteString(chainId)
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], epoch)
	buf.Write(epochBuf[:])
	buf.Write(txidRaw[:])
	buf.Write(rawTxHashRaw[:])
	buf.Write(instrHashRaw[:])

	digest := sha256.Sum256(buf.Bytes())
	return digest[:], nil
}

// ----- Forward queue state mgmt -----

// ForwardQueueEntry is the persisted record per IS-lock txid. Encoded as
// pipe-delimited string for v1 (no tinyjson dance); will move to tinyjson
// when the schema stabilises.
//
//	sender|instruction|callFunding|status
type ForwardQueueEntry struct {
	Sender      string
	Instruction string
	CallFunding int64
	Status      string
}

func (e *ForwardQueueEntry) serialize() string {
	return e.Sender + "|" + e.Instruction + "|" +
		strconv.FormatInt(e.CallFunding, 10) + "|" + e.Status
}

func parseForwardQueueEntry(raw string) (ForwardQueueEntry, error) {
	parts := strings.SplitN(raw, "|", 4)
	if len(parts) != 4 {
		return ForwardQueueEntry{}, ce.NewContractError(ce.ErrInput,
			"forwardQueue entry expected 4 fields, got "+strconv.Itoa(len(parts)))
	}
	cf, err := atoi64(parts[2])
	if err != nil {
		return ForwardQueueEntry{}, ce.NewContractError(ce.ErrInput,
			"invalid callFunding: "+parts[2])
	}
	return ForwardQueueEntry{
		Sender:      parts[0],
		Instruction: parts[1],
		CallFunding: cf,
		Status:      parts[3],
	}, nil
}

func saveForwardQueueEntry(txid string, entry ForwardQueueEntry) {
	sdk.StateSetObject(constants.ForwardQueueKeyPrefix+txid, entry.serialize())
}

func loadForwardQueueEntry(txid string) (ForwardQueueEntry, bool) {
	raw := sdk.StateGetObject(constants.ForwardQueueKeyPrefix + txid)
	if raw == nil || *raw == "" {
		return ForwardQueueEntry{}, false
	}
	entry, err := parseForwardQueueEntry(*raw)
	if err != nil {
		return ForwardQueueEntry{}, false
	}
	return entry, true
}

// ----- Per-DashDID rate limiter -----

// rateLimitState is windowStart_be8 || count_be4 — 12 bytes packed.
// Bumped into state under "rl/<did>" per spec §5.2.7.
func loadRateLimitState(did string) (windowStart uint64, count uint32) {
	raw := sdk.StateGetObject("rl/" + did)
	if raw == nil || len(*raw) != 12 {
		return 0, 0
	}
	b := []byte(*raw)
	windowStart = binary.BigEndian.Uint64(b[0:8])
	count = binary.BigEndian.Uint32(b[8:12])
	return
}

func saveRateLimitState(did string, windowStart uint64, count uint32) {
	var buf [12]byte
	binary.BigEndian.PutUint64(buf[0:8], windowStart)
	binary.BigEndian.PutUint32(buf[8:12], count)
	sdk.StateSetObject("rl/"+did, string(buf[:]))
}

// checkAndBumpRateLimit applies the per-DashDID sliding-window check and
// records the new count. Returns true if the call is allowed (under cap),
// false if rate-limited (over cap). Per spec §5.2.7, rate-limited calls
// still credit the IS amount but skip forward dispatch.
//
// "now" should be the current block timestamp in seconds. Contracts can
// read this via env.BlockHeight * blockTime, or — for the v1 scaffold —
// just use blockHeight as a rough clock since per-block monotonicity is
// all the sliding window needs.
func checkAndBumpRateLimit(did string, now uint64) bool {
	windowStart, count := loadRateLimitState(did)
	window := uint64(constants.PerDashDIDRateLimitWindowSec)
	if now-windowStart > window {
		// New window.
		saveRateLimitState(did, now, 1)
		return true
	}
	if int(count) >= constants.PerDashDIDRateLimitMax {
		return false
	}
	saveRateLimitState(did, windowStart, count+1)
	return true
}

// ----- Internal HBD ledger (extends BalancePrefix with asset axis) -----

// getInternalBalance returns the internal balance of `dashDID` in `asset`.
// asset="dash" uses the original BalancePrefix scheme (existing semantics);
// asset="hbd" uses the new internal-HBD scheme. See spec §5.2.6.
func getInternalBalance(dashDID, asset string) int64 {
	if asset == "dash" {
		return getAccBal(dashDID)
	}
	raw := sdk.StateGetObject(constants.BalancePrefix + asset + "/" + dashDID)
	if raw == nil || *raw == "" {
		return 0
	}
	var buf [8]byte
	copy(buf[8-len(*raw):], *raw)
	return int64(binary.BigEndian.Uint64(buf[:]))
}

func setInternalBalance(dashDID, asset string, newBal int64) {
	if asset == "dash" {
		setAccBal(dashDID, newBal)
		return
	}
	key := constants.BalancePrefix + asset + "/" + dashDID
	if newBal == 0 {
		sdk.StateDeleteObject(key)
		return
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(newBal))
	// Trim leading zero bytes for compactness.
	pos := 0
	for pos < 7 && buf[pos] == 0 {
		pos++
	}
	sdk.StateSetObject(key, string(buf[pos:]))
}

func incInternalBalance(dashDID, asset string, amount int64) error {
	bal := getInternalBalance(dashDID, asset)
	newBal, err := safeAdd64(bal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err,
			"error incrementing internal balance: "+dashDID+":"+asset)
	}
	setInternalBalance(dashDID, asset, newBal)
	return nil
}

func decInternalBalance(dashDID, asset string, amount int64) error {
	bal := getInternalBalance(dashDID, asset)
	if bal < amount {
		return ce.NewContractError(ce.ErrBalance,
			"insufficient "+asset+" balance: "+dashDID+
				" has "+strconv.FormatInt(bal, 10)+", needs "+strconv.FormatInt(amount, 10))
	}
	newBal, err := safeSubtract64(bal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err,
			"error decrementing internal balance")
	}
	setInternalBalance(dashDID, asset, newBal)
	return nil
}

// ----- Aliases shared with utils.go -----

func atoi64(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}
