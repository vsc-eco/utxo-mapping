package mapping

import (
	"btc-mapping-contract/contract/constants"
	ce "btc-mapping-contract/contract/contracterrors"
	"btc-mapping-contract/sdk"
	"strconv"
)

// HandleClaimRagnarok (U-4) returns the CALLER'S ENTIRE mapped balance to a BTC address by
// delegating to the existing unmap-to-L1 path (HandleUnmap), inheriting the Guard-1
// delete-at-confirm mechanics (pending "us-" record, reserved inputs, settle-at-confirm)
// verbatim — no duplicated withdrawal logic. Per-caller self-serve, 1:1, no cursor/exchange
// rate (mapped BTC is a flat a-<addr> balance, unlike THORChain's pooled LP shares).
//
// Ragnarök-only: the "claimRagnarok" export already gates on RagnarokModeKey before calling
// this (inverse of checkNotRagnarok); the check is re-asserted here as defense-in-depth so
// this handler is never reachable in a non-Ragnarök state even if called from elsewhere in
// the future.
//
// DeductFee=true always: the miner fee is netted out of the claim (there is no surplus
// balance to add it on top of — the caller is draining to exactly zero). From="" always:
// self-serve only, drawn from the caller's own balance — there is no allowance-based /
// unmapFrom-style variant for the return path (no stale-approval redirect risk).
//
// Interaction note (build-map §4b/§4c): getInputUtxoIds' D-1 filter selects ACTIVE-generation
// UTXOs only, so a claim is payable only from active-gen backing. If part of the vault's
// funds still sit under a retiring/draining/inactive generation when Ragnarök trips, the
// wind-down procedure is to keep calling migrateVault (kept LIVE under Ragnarök) until every
// superseded generation drains into the active generation, making every balance claimable.
// This handler does not — and structurally cannot — reach across generations itself.
func (cs *ContractState) HandleClaimRagnarok(to string) error {
	if s := sdk.StateGetObject(constants.RagnarokModeKey); s == nil || *s != "1" {
		return ce.NewContractError(ce.ErrTransaction, "claimRagnarok only available in ragnarok mode")
	}

	env := sdk.GetEnv()
	from := env.Caller.String()
	bal := getAccBal(from)
	if bal <= dustThreshold {
		return ce.NewContractError(ce.ErrBalance, "no claimable balance above dust")
	}

	instr := &TransferParams{
		Amount:    strconv.FormatInt(bal, 10),
		To:        to,
		DeductFee: true,
		From:      "",
	}
	return cs.HandleUnmap(instr)
}
