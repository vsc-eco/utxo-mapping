package mapping

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// Pentest finding BTC-C5: when buildSpendTransaction's available
// change is at or below the 546-sat dust threshold, the change
// output is omitted and the residual is implicitly absorbed by
// miners. The function previously returned the size-based fee
// estimate, not the actual outflow, so the caller's supply
// accounting (in HandleUnmap) was decremented by less than the
// real BTC consumed from the contract pool. Drift up to 545 sats
// per affected withdrawal accumulates as ActiveSupply > true
// pool size.
//
// Invariant under fix: for any successful return,
//   totalInputsAmount == sendAmount + sum(change_outputs) + fee
// In particular, when change is absorbed (no change output),
//   fee == totalInputsAmount - sendAmount
// regardless of how that compares to the size-based estimate.

func mustDecodePub(t *testing.T, h string) CompressedPubKey {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 33 {
		t.Fatalf("decode pubkey hex %q: %v (len %d)", h, err, len(b))
	}
	var k CompressedPubKey
	copy(k[:], b)
	return k
}

func newTestState(t *testing.T, baseFeeRate int64) *ContractState {
	t.Helper()
	primaryHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	backupHex := "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	params := &chaincfg.RegressionNetParams
	return &ContractState{
		PublicKeys: PublicKeys{
			Primary: mustDecodePub(t, primaryHex),
			Backup:  mustDecodePub(t, backupHex),
		},
		NetworkParams: params,
		Supply:        SystemSupply{BaseFeeRate: baseFeeRate},
	}
}

func mkInput(t *testing.T, amount int64) *Utxo {
	t.Helper()
	// 32-byte zero txid; the precise value doesn't affect fee accounting.
	return &Utxo{
		TxId:   "0000000000000000000000000000000000000000000000000000000000000001",
		Vout:   0,
		Amount: amount,
		Tag:    nil,
	}
}

func sumOutputs(t *testing.T, out [][2]int64) int64 {
	t.Helper()
	var s int64
	for _, o := range out {
		s += o[1]
	}
	return s
}

// regtestDestAddr returns a P2WPKH address derived from the backup
// pubkey on regtest — mirrors btctest_test.go's regtestDestAddress.
func regtestDestAddr(t *testing.T) string {
	t.Helper()
	backupHex := "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	b, err := hex.DecodeString(backupHex)
	if err != nil {
		t.Fatalf("decode backup pubkey: %v", err)
	}
	addr, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(b), &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("derive regtest dest address: %v", err)
	}
	return addr.EncodeAddress()
}

func TestBTCC5_DustAbsorbedFeeReportsActualOutflow(t *testing.T) {
	cs := newTestState(t, 1) // 1 sat/vbyte for predictable fees

	// Pick a sendAmount and inputs that leave a tiny residual after the
	// size-based fee — small enough that availableChange ≤ dustThreshold.
	// The exact crafting depends on the segwit fee curve; we iterate from
	// a generous input down until the function reports a fee with NO
	// change output, then assert the invariant.
	sendAmount := int64(100_000)

	for inputAmount := sendAmount + 200; inputAmount <= sendAmount+700; inputAmount++ {
		input := mkInput(t, inputAmount)
		changeAddr, _, err := AddressWithBackup(
			hex.EncodeToString(cs.PublicKeys.Primary[:]),
			hex.EncodeToString(cs.PublicKeys.Backup[:]),
			nil,
			cs.NetworkParams,
		)
		if err != nil {
			t.Fatalf("derive change address: %v", err)
		}

		tx, _, fee, err := cs.buildSpendTransaction(
			[]*Utxo{input},
			inputAmount,
			regtestDestAddr(t),
			changeAddr,
			sendAmount,
		)
		if err != nil {
			t.Fatalf("buildSpendTransaction(input=%d): %v", inputAmount, err)
		}

		// Sum the actual on-tx outputs.
		var outSum int64
		for _, o := range tx.TxOut {
			outSum += o.Value
		}
		actualFee := inputAmount - outSum

		// We're hunting the dust-absorbed branch: tx has only one output
		// (the destination), and the residual is wholly the fee.
		if len(tx.TxOut) == 1 {
			if fee != actualFee {
				t.Fatalf(
					"BTC-C5 leak (input=%d): dust absorbed but reported fee %d != actual outflow %d (delta %d sats)",
					inputAmount, fee, actualFee, actualFee-fee,
				)
			}
			// Found and validated the dust-absorbed case — done.
			t.Logf("dust-absorbed case found: input=%d fee=%d outSum=%d", inputAmount, fee, outSum)
			return
		}
	}

	t.Fatal("could not craft a dust-absorbed buildSpendTransaction case in the input range scanned; the test setup is wrong, not the contract")
}

func TestBTCC5_NormalChangeStillBalances(t *testing.T) {
	// Belt-and-braces: when change is well above dust, the invariant
	// totalInputs = sum(outputs) + fee must STILL hold — proving the fix
	// didn't regress the normal change-output path.
	cs := newTestState(t, 1)

	sendAmount := int64(50_000)
	inputAmount := int64(1_000_000) // huge change — well above dust

	changeAddr, _, err := AddressWithBackup(
		hex.EncodeToString(cs.PublicKeys.Primary[:]),
		hex.EncodeToString(cs.PublicKeys.Backup[:]),
		nil,
		cs.NetworkParams,
	)
	if err != nil {
		t.Fatalf("derive change address: %v", err)
	}

	tx, _, fee, err := cs.buildSpendTransaction(
		[]*Utxo{mkInput(t, inputAmount)},
		inputAmount,
		regtestDestAddr(t),
		changeAddr,
		sendAmount,
	)
	if err != nil {
		t.Fatalf("buildSpendTransaction: %v", err)
	}
	if len(tx.TxOut) < 2 {
		t.Fatalf("expected change output present (%d txouts)", len(tx.TxOut))
	}

	var outSum int64
	for _, o := range tx.TxOut {
		outSum += o.Value
	}
	if got := inputAmount - outSum; got != fee {
		t.Errorf("normal change path: actual outflow %d != reported fee %d", got, fee)
	}
}
