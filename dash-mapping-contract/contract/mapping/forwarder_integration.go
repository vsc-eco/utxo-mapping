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
	// Round-2 audit D2-DESIGN-08: defense-in-depth against attacker-
	// injected duplicate keys via a polluted ArgsB64 value. Track
	// every key encountered and reject second occurrences. The IS
	// service ALSO rejects ';' / '=' in user-supplied fields before
	// signing, but the contract is the security boundary and must not
	// trust upstream sanitization.
	seen := make(map[string]bool, 6)
	fields := strings.Split(instruction, constants.InstructionFieldDelimiter)
	for _, f := range fields {
		idx := strings.Index(f, constants.InstructionKVDelimiter)
		if idx < 0 {
			return out, ce.NewContractError(ce.ErrInput, "instruction field missing delimiter: "+f)
		}
		key := f[:idx]
		val := f[idx+1:]
		if seen[key] {
			return out, ce.NewContractError(ce.ErrInput, "duplicate instruction key: "+key)
		}
		seen[key] = true
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
	// sha256d (double-SHA-256) — Bitcoin's tx-hashing convention. We use
	// this for BOTH the txid slot and the rawTxHash slot in the signed
	// buffer. Earlier versions used single sha256 for rawTxHash, which
	// silently disagreed with the validator-side wire format and broke
	// every aggregate BLS verify. Pinned to the internal byte order;
	// the validator's CanonicalSigningMessage reverses display→internal
	// before writing to its buffer. See audit finding
	// `canonical-message-txid-byte-order-drift`.
	first := sha256.Sum256(rawTxBytes)
	txidInternal := sha256.Sum256(first[:])
	rawTxHashInternal := txidInternal // both slots carry sha256d(rawTx)
	instrHashRaw := sha256.Sum256([]byte(instruction))

	var buf bytes.Buffer
	buf.WriteString(dashISLockDomainPrefix)
	buf.WriteString(chainId)
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], epoch)
	buf.Write(epochBuf[:])
	buf.Write(txidInternal[:])
	buf.Write(rawTxHashInternal[:])
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
	window := constants.PerDashDIDRateLimitWindowBlocks
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

// ----- Validator-set-at-epoch lookup -----
//
// The contract's per-epoch validator set is admin-maintained for v1:
// the admin (or oracle) calls setValidatorSet at epoch turn with the
// pipe-delimited list of "<did>=<pubkey_hex>" entries. Once a
// production witness-state-read host fn exists, this gets swapped to
// read elections state directly. The on-disk format and check below
// stays the same — only the source-of-truth swaps.

// validatorSetForEpoch returns the {did → pubkeyHex} map registered
// for the given epoch and the block-height at which it was registered.
// Empty map + 0 if no admin-registered set.
//
// Storage format (audit `validator-set-fallback-uses-stale-set-indefinitely`):
//   "<registeredAt_block>#<did1>=<pk1>|<did2>=<pk2>|..."
//
// The leading registeredAt prefix lets verifyAttestationsAgainstValidatorSet
// bound the epoch-(N-1) fallback to ValidatorSetGraceBlocks.
func validatorSetForEpoch(epoch uint64) (map[string]string, uint64) {
	key := constants.ValidatorSetKeyPrefix + strconv.FormatUint(epoch, 10)
	raw := sdk.StateGetObject(key)
	if raw == nil || *raw == "" {
		return nil, 0
	}
	registeredAt, entriesStr := parseRegisteredAtPrefix(*raw)
	out := make(map[string]string)
	for _, entry := range strings.Split(entriesStr, constants.ValidatorSetEntryDelim) {
		if entry == "" {
			continue
		}
		i := strings.Index(entry, constants.ValidatorSetKVDelim)
		if i < 0 {
			continue
		}
		out[entry[:i]] = entry[i+1:]
	}
	return out, registeredAt
}

// parseRegisteredAtPrefix splits "<block>#rest" → (block, rest). For
// backward compat with the older format (no '#' prefix) returns (0, raw)
// — those entries don't get the grace-window fallback (treated as
// "registered at block 0" which is effectively infinitely stale, so
// only current-epoch matches survive). New admin writes always include
// the prefix.
func parseRegisteredAtPrefix(raw string) (uint64, string) {
	idx := strings.Index(raw, constants.ValidatorSetRegisteredAtDelim)
	if idx < 0 {
		return 0, raw
	}
	regAt, err := strconv.ParseUint(raw[:idx], 10, 64)
	if err != nil {
		return 0, raw[idx+1:]
	}
	return regAt, raw[idx+1:]
}

// serializeValidatorSet builds the admin-set payload from a {did →
// pubkeyHex} map. Stable ordering by DID-sorted-ascending so state
// hashes are deterministic. Includes the leading registeredAt prefix.
func serializeValidatorSet(registeredAt uint64, set map[string]string) string {
	dids := make([]string, 0, len(set))
	for did := range set {
		dids = append(dids, did)
	}
	// Insertion sort is fine — validator set is bounded by tens at most.
	for i := 1; i < len(dids); i++ {
		for j := i; j > 0 && dids[j-1] > dids[j]; j-- {
			dids[j-1], dids[j] = dids[j], dids[j-1]
		}
	}
	var b strings.Builder
	b.WriteString(strconv.FormatUint(registeredAt, 10))
	b.WriteString(constants.ValidatorSetRegisteredAtDelim)
	for i, did := range dids {
		if i > 0 {
			b.WriteString(constants.ValidatorSetEntryDelim)
		}
		b.WriteString(did)
		b.WriteString(constants.ValidatorSetKVDelim)
		b.WriteString(set[did])
	}
	return b.String()
}

// SaveValidatorSetForEpoch persists the admin-supplied set under the
// epoch's state key after verifying each entry's PoP. Stamps
// registeredAt with the current block height so the grace-window
// fallback can bound how long this set remains authoritative for the
// NEXT epoch.
//
// Audit R3-001: per-entry PoP verification closes the rogue-key
// aggregate-forgery hole — without it a rogue validator can register
// pk_attacker = pk_known − Σ(other_pks) and sign aggregates that
// "verify" as if the entire quorum signed.
//
// Audit R4-CSM-01 (round-4 follow-up): the PoP message MUST bind to
// the validator's Hive account name (not the BLS DID), because
// lib/dids/bls.go's canonical blsPoPMessage is
// `domain || pkBytes || accountBytes`. The admin payload threads the
// account as a 4th field per entry; the contract reconstructs the
// exact bytes the announcer signed.
func SaveValidatorSetForEpoch(epoch uint64, didToPubkey, didToPoP, didToAccount map[string]string) error {
	key := constants.ValidatorSetKeyPrefix + strconv.FormatUint(epoch, 10)
	if len(didToPubkey) == 0 {
		sdk.StateDeleteObject(key)
		return nil
	}
	// Per-DID PoP verify. Message MUST match lib/dids/bls.go's
	// blsPoPMessage: blsPoPDomain || pubkey || account.
	for did, pk := range didToPubkey {
		pop, ok := didToPoP[did]
		if !ok {
			return ce.NewContractError(ce.ErrInput,
				"PoP missing for validator "+did)
		}
		account, ok := didToAccount[did]
		if !ok || account == "" {
			return ce.NewContractError(ce.ErrInput,
				"account missing for validator "+did)
		}
		pkBytes, perr := hex.DecodeString(pk)
		if perr != nil || len(pkBytes) != 48 {
			return ce.NewContractError(ce.ErrInput,
				"pubkey decode failed for "+did)
		}
		var msgBuf bytes.Buffer
		msgBuf.WriteString(blsPoPDomain)
		msgBuf.Write(pkBytes)
		msgBuf.WriteString(account)
		msgHex := hex.EncodeToString(msgBuf.Bytes())
		if !sdk.VerifyBls(pk, msgHex, pop) {
			return ce.NewContractError(ce.ErrNoPermission,
				"BLS PoP failed to verify for validator "+did+" (account="+account+")")
		}
	}
	registeredAt := sdk.GetEnv().BlockHeight
	sdk.StateSetObject(key, serializeValidatorSet(registeredAt, didToPubkey))
	return nil
}

// blsPoPDomain MUST match lib/dids/bls.go's blsPoPDomain constant —
// drift would let a witness PoP generated under one domain be replayed
// for registration in the contract. The contract recomputes the PoP
// message and verifies via sdk.VerifyBls. Audit R3-001 / R4-CSM-01.
const blsPoPDomain = "VSC-BLS-POP-v1"

// ParseValidatorSetPayload parses the admin call payload format:
//
//	<epoch>;<did1>=<pubkey1>=<pop1>=<account1>|<did2>=<pubkey2>=<pop2>=<account2>|...
//
// pubkey is hex-encoded 48-byte compressed G1 (96 chars). PoP is a
// 96-byte BLS signature, hex-encoded (192 chars), produced by the
// validator under `blsPoPDomain || pubkey || account`. account is the
// validator's Hive account name (the same one the announcer's
// dids.GenerateBlsPoP bound the signature to — round-4 audit R4-CSM-01
// fixed the prior DID-vs-account divergence).
//
// Returns (epoch, didToPubkey, didToPoP, didToAccount, err). PoP
// verification runs in SaveValidatorSetForEpoch (it needs sdk.VerifyBls).
func ParseValidatorSetPayload(payload string) (uint64, map[string]string, map[string]string, map[string]string, error) {
	semi := strings.Index(payload, ";")
	if semi < 0 {
		return 0, nil, nil, nil, ce.NewContractError(ce.ErrInput,
			"validator-set payload expects '<epoch>;<entries>'")
	}
	epoch, err := strconv.ParseUint(payload[:semi], 10, 64)
	if err != nil {
		return 0, nil, nil, nil, ce.NewContractError(ce.ErrInput, "invalid epoch: "+payload[:semi])
	}
	entries := strings.Split(payload[semi+1:], constants.ValidatorSetEntryDelim)
	pubkeys := make(map[string]string, len(entries))
	pops := make(map[string]string, len(entries))
	accounts := make(map[string]string, len(entries))
	for _, e := range entries {
		if e == "" {
			continue
		}
		// Each entry is now did=pubkey=pop=account (four fields
		// delimited by '='). SplitN(4) is defensive against an
		// account name containing '=' (Hive usernames are
		// [a-z0-9.-] so this is belt-and-braces).
		parts := strings.SplitN(e, constants.ValidatorSetKVDelim, 4)
		if len(parts) != 4 {
			return 0, nil, nil, nil, ce.NewContractError(ce.ErrInput,
				"validator-set entry expects '<did>=<pubkey>=<pop>=<account>': "+e)
		}
		did, pk, pop, account := parts[0], parts[1], parts[2], parts[3]
		if did == "" || pk == "" || pop == "" || account == "" {
			return 0, nil, nil, nil, ce.NewContractError(ce.ErrInput,
				"validator-set entry has empty did, pubkey, pop, or account")
		}
		if len(pk) != 96 {
			return 0, nil, nil, nil, ce.NewContractError(ce.ErrInput,
				"pubkey must be 48 bytes (96 hex chars), got "+pk)
		}
		if len(pop) != 192 {
			return 0, nil, nil, nil, ce.NewContractError(ce.ErrInput,
				"pop must be 96 bytes (192 hex chars), got "+pop)
		}
		// Round-5 audit R5-ADV-02: enforce Hive's account-name
		// constraints so a malicious admin can't smuggle delimiters
		// or arbitrary bytes through the account field. Hive
		// usernames are [a-z0-9.-], 3..16 chars (per the Hive
		// consensus rules). Reject anything else.
		if len(account) < 3 || len(account) > 16 {
			return 0, nil, nil, nil, ce.NewContractError(ce.ErrInput,
				"account length must be 3..16, got "+account)
		}
		for i := 0; i < len(account); i++ {
			c := account[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'
			if !ok {
				return 0, nil, nil, nil, ce.NewContractError(ce.ErrInput,
					"account contains illegal char (allowed: [a-z0-9.-]): "+account)
			}
		}
		pubkeys[did] = pk
		pops[did] = pop
		accounts[did] = account
	}
	return epoch, pubkeys, pops, accounts, nil
}

// minAttestationsRequired reads the admin-configured quorum threshold.
// Defaults to DefaultMinAttestations when unset.
func minAttestationsRequired() int {
	raw := sdk.StateGetObject(constants.MinAttestationsKeyStateKey)
	if raw == nil || *raw == "" {
		return constants.DefaultMinAttestations
	}
	n, err := strconv.Atoi(*raw)
	if err != nil || n < 1 {
		return constants.DefaultMinAttestations
	}
	return n
}

// SaveMinAttestations persists the admin-supplied quorum threshold.
// Public for use by main.go's setMinAttestations entry.
func SaveMinAttestations(n int) error {
	if n < 1 {
		return ce.NewContractError(ce.ErrInput, "minAttestations must be >= 1")
	}
	sdk.StateSetObject(constants.MinAttestationsKeyStateKey, strconv.Itoa(n))
	return nil
}

// verifyAttestationsAgainstValidatorSet enforces that every attestation
// in body.Attestations belongs to the registered validator set at
// body.Epoch. Returns (count of recognised attesters, nil) on success,
// or (0, error) if any pubkey isn't in the set, the pubkey doesn't
// match the registered one for the claimed DID, or the validator set
// is empty.
//
// Epoch falls back to the previous epoch's set ONLY when:
//   (a) no set is registered for the requested epoch
//   (b) the previous epoch's set was registered within
//       ValidatorSetGraceBlocks of the current block height
// This bounds how long a kicked-out validator retains attestation
// authority after rotation — without the bound, an admin delay
// silently re-empowers the old set forever. Audit
// `validator-set-fallback-uses-stale-set-indefinitely`.
func verifyAttestationsAgainstValidatorSet(
	attestations []ValidatorAttestation,
	epoch uint64,
) (int, error) {
	set, _ := validatorSetForEpoch(epoch)
	if len(set) == 0 && epoch > 0 {
		prevSet, prevRegisteredAt := validatorSetForEpoch(epoch - 1)
		if len(prevSet) > 0 {
			currentBlock := sdk.GetEnv().BlockHeight
			// Reject the fallback if either:
			//   - prevRegisteredAt is 0 (legacy / pre-grace-format entry)
			//   - the bound has elapsed
			if prevRegisteredAt > 0 && currentBlock-prevRegisteredAt <= constants.ValidatorSetGraceBlocks {
				set = prevSet
			}
		}
	}
	if len(set) == 0 {
		return 0, ce.NewContractError(ce.ErrNoPermission,
			"no validator set registered for epoch "+strconv.FormatUint(epoch, 10)+
				" (and previous-epoch grace window expired or unavailable)")
	}

	count := 0
	seen := make(map[string]struct{}, len(attestations))
	for _, a := range attestations {
		if _, dup := seen[a.ValidatorDID]; dup {
			return 0, ce.NewContractError(ce.ErrInput,
				"duplicate attestation from "+a.ValidatorDID)
		}
		registered, ok := set[a.ValidatorDID]
		if !ok {
			return 0, ce.NewContractError(ce.ErrNoPermission,
				"attestation from non-registered validator: "+a.ValidatorDID)
		}
		if registered != a.PubkeyHex {
			return 0, ce.NewContractError(ce.ErrNoPermission,
				"attestation pubkey mismatch for "+a.ValidatorDID+
					": expected "+registered+", got "+a.PubkeyHex)
		}
		seen[a.ValidatorDID] = struct{}{}
		count++
	}
	return count, nil
}

// ----- Allow-list governance timelock -----

// ProposeAllowedTargetAdd schedules an add at the current block height +
// timelock. Caller (main.go) gates by admin check.
//
// Refuses if the target is already in the active allow-list, if a
// pending-add already exists (would silently extend the timelock —
// audit `propose-allowed-target-no-pending-conflict-check`), or if a
// conflicting pending-remove exists for the same target.
func ProposeAllowedTargetAdd(targetId string, currentBlock uint64) error {
	if isTargetAllowed(targetId) {
		return ce.NewContractError(ce.ErrInput,
			"target "+targetId+" is already in the allow-list")
	}
	if existing := sdk.StateGetObject(constants.PendingAllowedTargetAddKeyPrefix + targetId); existing != nil && *existing != "" {
		return ce.NewContractError(ce.ErrInput,
			"target "+targetId+" already has a pending add (cancel first)")
	}
	if existing := sdk.StateGetObject(constants.PendingAllowedTargetRemoveKeyPrefix + targetId); existing != nil && *existing != "" {
		return ce.NewContractError(ce.ErrInput,
			"target "+targetId+" has a conflicting pending remove (cancel it first)")
	}
	unlock := currentBlock + constants.AllowListGovernanceTimelockBlocks
	sdk.StateSetObject(
		constants.PendingAllowedTargetAddKeyPrefix+targetId,
		strconv.FormatUint(unlock, 10),
	)
	return nil
}

// CommitAllowedTarget promotes a pending add to the active allow-list
// if the timelock has elapsed. Returns (didCommit, unlockBlock, err).
func CommitAllowedTarget(targetId string, currentBlock uint64) (bool, uint64, error) {
	raw := sdk.StateGetObject(constants.PendingAllowedTargetAddKeyPrefix + targetId)
	if raw == nil || *raw == "" {
		return false, 0, ce.NewContractError(ce.ErrInput,
			"no pending add for target "+targetId)
	}
	unlock, err := strconv.ParseUint(*raw, 10, 64)
	if err != nil {
		return false, 0, ce.NewContractError(ce.ErrInput,
			"pending add unlock corrupted: "+*raw)
	}
	if currentBlock < unlock {
		return false, unlock, nil
	}
	sdk.StateSetObject(constants.AllowedTargetsKeyPrefix+targetId, "1")
	sdk.StateDeleteObject(constants.PendingAllowedTargetAddKeyPrefix + targetId)
	return true, unlock, nil
}

// proposeAllowedTargetRemove + commitAllowedTargetRemove mirror the add
// flow. Symmetric so additions and revocations have the same
// transparency window — the spec calls this out as a defense-in-depth
// move so adversaries can't censor a target by getting it removed
// faster than the community can react.
// ProposeAllowedTargetRemove schedules a remove at currentBlock + timelock.
// Refuses if the target isn't on the allow-list, if a pending-remove
// already exists, or if a pending-add for the same target exists.
func ProposeAllowedTargetRemove(targetId string, currentBlock uint64) error {
	if !isTargetAllowed(targetId) {
		return ce.NewContractError(ce.ErrInput,
			"target "+targetId+" is not on the allow-list")
	}
	if existing := sdk.StateGetObject(constants.PendingAllowedTargetRemoveKeyPrefix + targetId); existing != nil && *existing != "" {
		return ce.NewContractError(ce.ErrInput,
			"target "+targetId+" already has a pending remove (cancel first)")
	}
	if existing := sdk.StateGetObject(constants.PendingAllowedTargetAddKeyPrefix + targetId); existing != nil && *existing != "" {
		return ce.NewContractError(ce.ErrInput,
			"target "+targetId+" has a conflicting pending add (cancel it first)")
	}
	unlock := currentBlock + constants.AllowListGovernanceTimelockBlocks
	sdk.StateSetObject(
		constants.PendingAllowedTargetRemoveKeyPrefix+targetId,
		strconv.FormatUint(unlock, 10),
	)
	return nil
}

// CommitAllowedTargetRemove finalises a pending removal once timelock elapsed.
func CommitAllowedTargetRemove(targetId string, currentBlock uint64) (bool, uint64, error) {
	raw := sdk.StateGetObject(constants.PendingAllowedTargetRemoveKeyPrefix + targetId)
	if raw == nil || *raw == "" {
		return false, 0, ce.NewContractError(ce.ErrInput,
			"no pending remove for target "+targetId)
	}
	unlock, err := strconv.ParseUint(*raw, 10, 64)
	if err != nil {
		return false, 0, ce.NewContractError(ce.ErrInput,
			"pending remove unlock corrupted: "+*raw)
	}
	if currentBlock < unlock {
		return false, unlock, nil
	}
	sdk.StateDeleteObject(constants.AllowedTargetsKeyPrefix + targetId)
	sdk.StateDeleteObject(constants.PendingAllowedTargetRemoveKeyPrefix + targetId)
	return true, unlock, nil
}

// CancelPendingAllowedTargetAdd / Remove let admin abort a proposal
// inside the timelock window. Symmetric for both directions.
func CancelPendingAllowedTargetAdd(targetId string) {
	sdk.StateDeleteObject(constants.PendingAllowedTargetAddKeyPrefix + targetId)
}

// CancelPendingAllowedTargetRemove deletes a pending remove proposal.
func CancelPendingAllowedTargetRemove(targetId string) {
	sdk.StateDeleteObject(constants.PendingAllowedTargetRemoveKeyPrefix + targetId)
}
