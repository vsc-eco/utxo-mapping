package current_test

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"testing"

	"btc-mapping-contract/contract/constants"
	"btc-mapping-contract/contract/mapping"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/require"
	"vsc-node/lib/btcvault"
	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
)

// What Altera and the BTC/HBD pool see across a full rotation (vault-rotation-v2 with
// VR2-12 and the WQ-1 queue), through the real router and pool:
//
//	ALT-*   altera-app's rotation notice (vaultRotation.ts, 051a988), recomputed from the
//	        three keys it reads ("v", "va", "msl") with its own rules: rotating = a
//	        generation is RETIRING or DRAINING, sweeping = "msl" is not empty, preparing =
//	        a generation is PENDING.
//	POOL-*  moving custody never moves the pool: its reserves and the balances it holds on
//	        the vault are identical before and after each custody step, and swaps that stay
//	        on Magi keep working while the old generation drains.
//	WIN-*   withdrawals in the window: a user's own withdrawal is queued (WQ-1); a swap
//	        paid out to a Bitcoin address goes through the router, which WQ-1 does not
//	        queue, so it is recorded here as it behaves.
//
// Needs DEX_CONTRACTS_BIN like TestSwapMigrationThroughRealDex.

type alteraVerdict struct {
	rotating, sweeping, preparing bool
	activeGen                     int64
}

// alteraView decodes the vault keys the way vaultRotation.ts does: 91-byte entries, the
// generation at [0:4], the status byte at [70].
func alteraView(ct *test_utils.ContractTest) alteraVerdict {
	v := []byte(ct.StateGet(swapMigMapping, constants.VaultRegistryKey))
	var out alteraVerdict
	for off := 0; off+91 <= len(v); off += 91 {
		switch v[off+70] {
		case 0:
			out.preparing = true
		case 2, 3:
			out.rotating = true
		}
	}
	out.sweeping = ct.StateGet(swapMigMapping, constants.MigrationSweepRegistryKey) != ""
	out.activeGen = -1
	if va := []byte(ct.StateGet(swapMigMapping, constants.VaultActiveGenKey)); len(va) >= 4 {
		out.activeGen = int64(binary.BigEndian.Uint32(va))
	}
	return out
}

type poolView struct {
	r0, r1     string
	btcOnVault int64
	hbd, lpBTC int64
}

func poolSnapshot(t *testing.T, ct *test_utils.ContractTest) poolView {
	return poolView{
		r0:         ct.StateGet(swapMigPool, "r0"),
		r1:         ct.StateGet(swapMigPool, "r1"),
		btcOnVault: swapMigBal(t, ct, "contract:"+swapMigPool),
		hbd:        swapMigHBD(ct, "contract:"+swapMigPool),
		lpBTC:      swapMigBal(t, ct, swapMigOwner),
	}
}

// booksGap is Sigma(registry) - (Active + Fee + queued escrow); it must not change.
func booksGap(t *testing.T, ct *test_utils.ContractTest) int64 {
	s := loadSupply(t, ct, swapMigMapping)
	require.Equal(t, s.ActiveSupply, s.UserSupply, "I2: Active == User")
	return sumRegistry(t, ct, swapMigMapping) - (s.ActiveSupply + s.FeeSupply + wqQueuedEscrow(t, ct, swapMigMapping))
}

func routerSwap(t *testing.T, ct *test_utils.ContractTest, caller, assetIn, assetOut string, amount int64, recipient, chain string) test_utils.ContractTestCallResult {
	t.Helper()
	body := map[string]any{"type": "swap", "version": "1.0.0", "asset_in": assetIn, "asset_out": assetOut,
		"amount_in": strconv.FormatInt(amount, 10), "recipient": recipient}
	if chain != "" {
		body["destination_chain"] = chain
	}
	allow := contracts.Intent{Type: "transfer.allow", Args: map[string]string{"token": assetIn, "limit": strconv.FormatInt(amount, 10)}}
	if assetIn == "btc" {
		allow.Args["contract_id"] = swapMigMapping
	}
	return swapMigCall(t, ct, swapMigRouter, caller, "execute", swapMigJSON(t, body), []contracts.Intent{allow}, 100_000)
}

// botDepositKey picks the deposit key the way the mapping bot does (FetchPublicKeys,
// mapper/graphql_client.go): decode "v" with lib/btcvault and take the generation named by
// "va", which must be ACTIVE. Altera shows the address the bot derives from this key.
func botDepositKey(t *testing.T, ct *test_utils.ContractTest) string {
	t.Helper()
	vaults, err := btcvault.UnmarshalVaultRegistry([]byte(ct.StateGet(swapMigMapping, constants.VaultRegistryKey)))
	require.NoError(t, err)
	active, ok := btcvault.ReadUint32BE([]byte(ct.StateGet(swapMigMapping, constants.VaultActiveGenKey)))
	require.True(t, ok)
	for _, v := range vaults {
		if v.Generation == active {
			require.Equal(t, btcvault.VaultStatusActive, v.Status, "the bot refuses a non-active generation")
			return hex.EncodeToString(v.Primary)
		}
	}
	t.Fatalf("active generation %d not in the registry", active)
	return ""
}

func TestAlteraPools_AcrossRotation(t *testing.T) {
	ct := newSwapMigCT(t)
	const user = "hive:swapmig-user"
	const trader = "hive:swapmig-w14" // "hive:"+name must stay under 17 chars or ledger Deposit credits the sender (ledger_system.go:1549-1553)

	// gen-0 holds a real deposit for `user`.
	r := swapMigMap(t, ct, TestPrimaryPubKeyHex, "deposit_to="+user, 3_000_000, 100)
	require.True(t, r.Success, "deposit: %s %s", r.Err, r.ErrMsg)
	gap0 := booksGap(t, ct)

	require.Equal(t, alteraVerdict{activeGen: 0}, alteraView(ct), "ALT-IDLE: one active generation, no notice")
	require.Equal(t, TestPrimaryPubKeyHex, botDepositKey(t, ct), "BOT-ADDR: gen-0's key")

	// Mint and register gen-1: Altera reports "preparing" only; the live vault is untouched.
	require.Empty(t, callKeyAction(t, ct, swapMigMapping, swapMigOwner, "createKey", []byte("")).Err)
	require.Empty(t, callKeyAction(t, ct, swapMigMapping, swapMigOwner, "registerPublicKey", regKeyPayload(t, Gen1PrimaryHex, "")).Err)
	require.Equal(t, alteraVerdict{preparing: true, activeGen: 0}, alteraView(ct), "ALT-PREPARING")

	// VR2-12: check-signed but not reshared, so activation is refused and nothing changes for Altera.
	setTssKeyProof(t, ct, swapMigMapping, "mainv1", Gen1PrimaryHex, 0, true)
	r = callKeyAction(t, ct, swapMigMapping, swapMigOwner, "activateKey", []byte(""))
	require.Contains(t, r.ErrMsg, "VR2-12")
	require.Equal(t, alteraVerdict{preparing: true, activeGen: 0}, alteraView(ct), "ALT-PREPARING while the reshare is pending")
	// VR2-12 keeps gen-1 pending longer (until its first reshare); the bot keeps handing out
	// gen-0's address, and a deposit made then joins gen-0 and is swept with it.
	require.Equal(t, TestPrimaryPubKeyHex, botDepositKey(t, ct), "BOT-ADDR-PENDING: still gen-0's key while gen-1 is pending")
	before := registryIds(t, ct, swapMigMapping)
	r = swapMigMap(t, ct, botDepositKey(t, ct), "deposit_to="+user, 400_000, 104)
	require.True(t, r.Success, "BOT-ADDR-PENDING deposit: %s %s", r.Err, r.ErrMsg)
	ids := newUtxoIds(before, registryIds(t, ct, swapMigMapping))
	require.Len(t, ids, 1)
	require.Equal(t, uint32(0), utxoGenerationForId(t, ct, swapMigMapping, ids[0]), "BOT-ADDR-PENDING: the deposit joins gen-0")
	gap0 = booksGap(t, ct)

	setTssKeyProof(t, ct, swapMigMapping, "mainv1", Gen1PrimaryHex, 1, true)
	pool := poolSnapshot(t, ct)
	require.Empty(t, callKeyAction(t, ct, swapMigMapping, swapMigOwner, "activateKey", []byte("")).Err)
	require.Equal(t, alteraVerdict{rotating: true, activeGen: 1}, alteraView(ct), "ALT-ROTATING after activation")
	require.Equal(t, Gen1PrimaryHex, botDepositKey(t, ct), "BOT-ADDR-WINDOW: gen-1's key as soon as it is active")
	require.Equal(t, pool, poolSnapshot(t, ct), "POOL-ACTIVATE: activation moves nothing in the pool")
	require.Equal(t, gap0, booksGap(t, ct))

	// Swaps that stay on Magi work while gen-0 is retiring.
	ct.Deposit(trader, 3_000_000, "hbd")
	r = routerSwap(t, ct, trader, "hbd", "btc", 200_000, trader, "")
	require.True(t, r.Success, "POOL-L2-HBD-BTC in the window: %s %s", r.Err, r.ErrMsg)
	got := swapMigBal(t, ct, trader)
	require.Greater(t, got, int64(0), "POOL-L2-HBD-BTC: the trader holds wrapped BTC")
	allow, err := tinyjson.Marshal(mapping.AllowanceParams{Spender: "contract:" + swapMigRouter, Amount: strconv.FormatInt(got, 10)})
	require.NoError(t, err)
	require.True(t, callAs(t, ct, swapMigMapping, trader, "increaseAllowance", allow).Success, "the trader approves the router, as Altera does")
	r = routerSwap(t, ct, trader, "btc", "hbd", got/2, trader, "")
	require.True(t, r.Success, "POOL-L2-BTC-HBD in the window: %s %s", r.Err, r.ErrMsg)
	require.Equal(t, gap0, booksGap(t, ct), "POOL-L2: swaps on Magi leave the vault's books unchanged")

	// WIN-QUEUE: the user's own withdrawal is accepted and queued (gen-1 holds no coins yet).
	r = wqUnmap(t, ct, swapMigMapping, user, 500_000)
	require.True(t, r.Success, "WIN-QUEUE: %s %s", r.Err, r.ErrMsg)
	head, tail := wqBounds(t, ct, swapMigMapping)
	require.Equal(t, uint32(1), tail-head, "WIN-QUEUE: one queued withdrawal")

	// WIN-SWAP-L1: a swap paid out to a Bitcoin address in the same window.
	hbdBefore, poolBefore, pendBefore := swapMigHBD(ct, trader), poolSnapshot(t, ct), ct.StateGet(swapMigMapping, constants.TxSpendsRegistryKey)
	r = routerSwap(t, ct, trader, "hbd", "btc", 200_000, regtestDestAddress(t), "BTC")
	// Not queued (WQ-1 queues only a user's own direct withdrawal), so the whole swap reverts,
	// says the coins are held, and nothing moves.
	require.False(t, r.Success, "WIN-SWAP-L1: a router payout to Bitcoin is refused while gen-1 holds no free coin")
	require.Contains(t, r.ErrMsg, "vault coins are held", "WIN-SWAP-L1: the refusal says why")
	require.Equal(t, hbdBefore, swapMigHBD(ct, trader), "WIN-SWAP-L1 refused: the trader keeps the HBD")
	require.Equal(t, poolBefore, poolSnapshot(t, ct), "WIN-SWAP-L1 refused: the pool is untouched")
	require.Equal(t, pendBefore, ct.StateGet(swapMigMapping, constants.TxSpendsRegistryKey), "WIN-SWAP-L1 refused: nothing to sign")
	require.Equal(t, gap0, booksGap(t, ct))

	// The sweep: Altera shows "sweeping" while it is in flight; the pool does not move.
	pool = poolSnapshot(t, ct)
	r = callKeyAction(t, ct, swapMigMapping, swapMigOwner, "migrateVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	sweep := r.Ret
	require.Equal(t, alteraVerdict{rotating: true, sweeping: true, activeGen: 1}, alteraView(ct), "ALT-SWEEPING")
	require.Equal(t, pool, poolSnapshot(t, ct), "POOL-SWEEP-BUILT")
	require.True(t, confirmMigrationSweep(t, ct, swapMigMapping, swapMigOwner, sweep, 300).Success)
	require.Equal(t, pool, poolSnapshot(t, ct), "POOL-SWEEP-SETTLED: custody moved, the pool did not")
	v := alteraView(ct)
	t.Logf("after the settle: %+v, queue %v", v, func() []uint32 { h, tl := wqBounds(t, ct, swapMigMapping); return []uint32{h, tl} }())
	require.False(t, v.sweeping, "ALT: no sweep in flight after the settle")
	require.True(t, v.rotating, "ALT: the emptied gen-0 is DRAINING until retireVault, so the notice stays up until then")
	head, tail = wqBounds(t, ct, swapMigMapping)
	require.Equal(t, head, tail, "WIN-QUEUE: the settle drains the queued withdrawal")

	// SWEEP-SPLIT: the sweep paid gen-1 in one coin per input (two here), so the drained
	// withdrawal takes one and a payout to Bitcoin goes out on the other right away.
	g1 := 0
	for id := range registryIds(t, ct, swapMigMapping) {
		if utxoGenerationForId(t, ct, swapMigMapping, id) == 1 {
			g1++
		}
	}
	require.Equal(t, 2, g1, "SWEEP-SPLIT: gen-1 holds two coins after a two-input sweep")
	require.Len(t, wqPending(t, ct, swapMigMapping), 1, "the drained withdrawal is the one spend in flight")
	r = routerSwap(t, ct, trader, "hbd", "btc", 200_000, regtestDestAddress(t), "BTC")
	require.True(t, r.Success, "AFTER-SETTLE-SWAP-L1: a payout to Bitcoin goes out on the second coin: %s", r.ErrMsg)
	// Both coins are now in flight: the next direct withdrawal is queued, not refused.
	r = wqUnmap(t, ct, swapMigMapping, user, 300_000)
	require.True(t, r.Success, "AFTER-SETTLE-UNMAP: a direct withdrawal is queued: %s", r.ErrMsg)
	head, tail = wqBounds(t, ct, swapMigMapping)
	require.Equal(t, uint32(1), tail-head, "AFTER-SETTLE-UNMAP: queued, not refused")
	// ...and a payout through the router says why it cannot wait.
	r = routerSwap(t, ct, trader, "hbd", "btc", 200_000, regtestDestAddress(t), "BTC")
	require.False(t, r.Success, "AFTER-SETTLE-SWAP-L1-BUSY: no free coin left")
	require.Contains(t, r.ErrMsg, "vault coins are held")

	// retireVault ends the rotation for Altera; it moves nothing in the pool.
	pool = poolSnapshot(t, ct)
	r = callKeyAction(t, ct, swapMigMapping, swapMigOwner, "retireVault", []byte(""))
	require.Empty(t, r.Err, r.ErrMsg)
	v = alteraView(ct)
	require.False(t, v.rotating, "ALT-DONE: the notice clears once gen-0 is retired")
	require.Equal(t, Gen1PrimaryHex, botDepositKey(t, ct), "BOT-ADDR-DONE")
	require.Equal(t, pool, poolSnapshot(t, ct), "POOL-RETIRE")

	// Every withdrawal in flight confirms (each settle drains the next queued one): the books
	// are exact again, the queue is empty, and payouts to Bitcoin flow.
	h := uint32(310)
	for i := 0; i < 4; i++ {
		p := wqPending(t, ct, swapMigMapping)
		if len(p) == 0 {
			break
		}
		for _, tx := range p {
			require.True(t, confirmMigrationSweep(t, ct, swapMigMapping, swapMigOwner, tx, h).Success)
			h += 10
		}
	}
	require.Empty(t, wqPending(t, ct, swapMigMapping))
	head, tail = wqBounds(t, ct, swapMigMapping)
	require.Equal(t, head, tail, "queue empty")
	require.Equal(t, gap0, booksGap(t, ct), "books unchanged across the whole rotation")
	r = routerSwap(t, ct, trader, "hbd", "btc", 200_000, regtestDestAddress(t), "BTC")
	require.True(t, r.Success, "POOL-L1-AFTER: a swap paid out to Bitcoin works once the drained withdrawal confirmed: %s", r.ErrMsg)
}
