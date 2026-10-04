package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"bytes"
	"encoding/hex"
	"strconv"

	"github.com/btcsuite/btcd/wire"
)

// theft_gate.go — M1.1b rogue-spend auto-trip (Build-Map §5b; THORChain SlashVault-derived).
//
// THORChain's real anti-theft is not "destroy the key" — it is "detect an outbound you did
// not authorise, then halt+slash" (handler_common_outbound.go → SlashVault). Magi maps this
// EASIER than THORChain: the per-UTXO registry lets us positively identify which vault UTXO
// was spent, and an SPV Merkle proof is cryptographic, so ONE honest report is sufficient —
// no 2/3 observation vote is needed (THORChain needs the quorum only because bifrost
// observations aren't proven).
//
// ★ COVERAGE BOUNDARY (M1.1b council, corrected from an earlier overclaim). This trip
// detects theft of a CURRENTLY-REGISTERED vault UTXO ONLY. It is a theft-detection LAYER for
// the live vault, NOT "the guarantee that makes never-destroy complete" — the S5 never-destroy
// stance is safe on its own (an empty, address-RETIRED vault's key steals nothing). What this
// trip does NOT catch (a rogue TSS can drain these without tripping — all require a compromised
// committee, the fundamental TSS threat; bounded, not full-vault):
//   - an UN-MAPPED deposit (on the vault address but not yet `map`'d → no registry entry) — the
//     complement is the L1-balance-vs-Supply SOLVENCY WATCH (node observeBtcSolvencyInsolvent);
//   - a migration sweep's successor OUTPUT during the confirm-lag (indexed only at settle) —
//     fix: index the sweep output as unconfirmed at build (like unmap change);
//   - a delete-at-BUILD unmap's inputs if the unmap tx never confirms (no RBF) — fix: unmap
//     delete-at-CONFIRM (BRK-1-style), which also closes the S5.0 fund-safety F1/F2 concern;
//   - a reorg'd-back UTXO (3+ block reorg, essentially never on mainnet).
// The complete live-vault theft-detection = THIS SPV trip (registered-UTXO drains) + the
// solvency watch (registered-pool drains via un-registered paths). Those complements are the
// observation-model work; they are tracked, not built here. A legit CSV-backup-branch spend
// also trips (txid ∉ TxSpendsList) — intended: an anomalous backup recovery is worth halting
// keysign on (the TSS is presumably non-functional if the backup path is being exercised).

// HandleReportUnauthorizedSpend takes an SPV proof of a confirmed BTC tx. If that tx spends
// a CURRENTLY-REGISTERED vault UTXO whose spending txid is NOT an authorised in-flight spend
// (∉ cs.TxSpendsList), it is an unauthorised drain of the vault → it sets the deterministic
// BtcTheftHaltKey flag that the node's TSS solvency gate reads (M1.1a auto-trip). It moves
// NO funds and is PERMISSIONLESS (any honest party submits the proof) and NOT pause-gated
// (a theft during a pause must still halt).
//
// Deterministic + consensus-re-executed: SPV verify (header from committed state) + a keyed
// lookup set (never ranged for output) + slice-order registry scan with keyed UTXO loads.
// Every node reaches the identical verdict and sets the identical flag byte.
//
// ★ Correctness — why NO append-only authorised-tx ledger (the V-7 concern) is needed: a
// spend's inputs LEAVE the registry when spent — an unmap deletes its inputs at build, a
// migration sweep at confirm (BRK-1 delete-at-confirm). Therefore:
//   (a) a CONFIRMED legit spend no longer spends a registered UTXO → step 2 (registry
//       membership) already excludes it. This is exactly the V-7 "a deleted-from-the-live-
//       list confirmed withdrawal must not false-halt" case — closed by the UTXO leaving
//       the registry, not by remembering the txid forever.
//   (b) an UNCONFIRMED legit spend's inputs are still registered, but its txid IS in
//       cs.TxSpendsList (both the unmap path, handlers.go, and the migration path,
//       migration.go, append there; MigrationSweeps ⊆ TxSpendsList) → step 3 excludes it.
//   (c) a rogue spend spends a still-registered UTXO (the contract never authorised the
//       spend, so it never deleted the UTXO) with a txid ∉ cs.TxSpendsList → TRIP.
// The residual (a rogue spend of a UTXO that an unmap deleted-at-build but whose unmap tx
// never confirmed) is the pre-existing unmap delete-at-build gap, out of scope here. The
// S5/M1.1b council must independently try to break this "no append-only needed" claim.
func (cs *ContractState) HandleReportUnauthorizedSpend(txData *VerificationRequest) error {
	if txData == nil || txData.RawTxHex == "" {
		return ce.NewContractError(ce.ErrInput, "tx_data.raw_tx_hex required")
	}
	rawTx, err := hex.DecodeString(txData.RawTxHex)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "invalid raw tx hex")
	}
	// ★ NO CONFIRMATION-DEPTH GATE HERE, DELIBERATELY. Do not "fix" this by adding
	// requireConfirmationDepth to match map / confirmSpend / topUpFeeReserve (VR2-07,
	// VR2-25). Those three CREDIT: they create a claim on money, so a proof from a block
	// that later vanishes leaves phantom supply, and waiting costs only deposit latency.
	// This one is an ALARM. It moves no funds, it sets a flag the node's solvency gate
	// reads, and the flag is owner-clearable (clearTheftHalt). Gating it on depth would
	// hand a genuine thief the whole gate's worth of head start (~40 minutes on mainnet)
	// to buy protection against a spurious halt that an owner can clear in one call. The
	// costs run opposite ways on a crediting path and on an alarm, so the guards should
	// too. There is also already an implicit margin: the header must be in committed
	// state, and the oracle only relays headers validityThreshold blocks behind the tip.
	//
	// The block header must be present, else verifyTransaction dereferences a nil header
	// (proof.go:22). A spend whose block is pruned or was never submitted cannot be
	// SPV-proven → reject cleanly (never a false trip on an unprovable report).
	hdr := sdk.StateGetObject(constants.BlockPrefix + strconv.FormatUint(uint64(txData.BlockHeight), 10))
	if hdr == nil || len(*hdr) == 0 {
		return ce.NewContractError(ce.ErrInput, "block header not available for the reported spend height")
	}
	if err := verifyTransaction(txData, rawTx); err != nil {
		return ce.Prepend(err, "error verifying reported spend")
	}
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(rawTx)); err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "could not deserialize reported tx")
	}

	// Load the current registry (keyed loads, slice order — deterministic), then run the
	// pure classification. FN-5 (council): a single unreadable entry (a registry↔blob desync;
	// no known path produces one — deletes are paired — but defense-in-depth) must NOT disable
	// the whole detector. SKIP the bad entry (that one UTXO is momentarily un-checked) rather
	// than aborting the report. Deterministic: a missing/corrupt committed blob is identical on
	// all nodes. Failing the report CLOSED on any load error would let a single corruption
	// silently kill the theft detector network-wide — the wrong direction for a safety gate.
	registered := make([]*Utxo, 0, len(cs.UtxoList))
	for i := range cs.UtxoList {
		utxo, lerr := loadUtxo(cs.UtxoList[i].Id)
		if lerr != nil {
			sdk.Log("warn|theft-gate|unreadable-utxo|" + strconv.FormatUint(uint64(cs.UtxoList[i].Id), 10))
			continue
		}
		registered = append(registered, utxo)
	}
	spendsRegistered, authorized := classifyReportedSpend(&msgTx, registered, cs.TxSpendsList)
	if !spendsRegistered || authorized {
		// Spends nothing the vault currently holds (a confirmed legit spend's inputs already
		// left the registry), or it is an authorised in-flight spend → no trip.
		return nil
	}

	// UNAUTHORISED spend of a registered vault UTXO → TRIP the deterministic halt flag.
	sdk.StateSetObject(constants.BtcTheftHaltKey, "1")
	sdk.Log("security|btc-theft-halt|" + msgTx.TxID())
	return nil
}

// classifyReportedSpend is the PURE M1.1b decision over an already-SPV-verified tx, the
// already-loaded registry, and the authorised in-flight set. Extracted so the trip decision
// is unit-testable off-chain (the SPV verify + sdk state I/O stay in the handler). Returns:
//   - spendsRegistered: at least one tx input's outpoint matches a currently-registered
//     vault UTXO (txid:vout);
//   - authorized: the tx's own txid is an authorised in-flight spend (∈ txSpends).
// A trip fires iff spendsRegistered && !authorized. The spent-outpoint set is a map used
// ONLY for lookups (never ranged for output) → determinism-safe; the registry is scanned in
// slice order.
func classifyReportedSpend(msgTx *wire.MsgTx, registered []*Utxo, txSpends []string) (spendsRegistered, authorized bool) {
	spent := make(map[string]bool, len(msgTx.TxIn))
	for _, in := range msgTx.TxIn {
		spent[in.PreviousOutPoint.Hash.String()+":"+strconv.FormatUint(uint64(in.PreviousOutPoint.Index), 10)] = true
	}
	for _, u := range registered {
		if spent[u.TxId+":"+strconv.FormatUint(uint64(u.Vout), 10)] {
			spendsRegistered = true
			break
		}
	}
	txId := msgTx.TxID()
	for _, id := range txSpends {
		if id == txId {
			authorized = true
			break
		}
	}
	return spendsRegistered, authorized
}
