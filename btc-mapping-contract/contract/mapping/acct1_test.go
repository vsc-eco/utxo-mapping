package mapping

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// ACCT-1 characterization: a deduct_fee unmap charges the user `amount` and sends
// amount - vscFee - estimate, but the vault loses sendAmount + TRUE fee (inputs -
// outputs). Mirrors HandleUnmap's deduct_fee arithmetic with the real estimator and
// builder, reports how far the OLD debit (`amount`) let Σ(UTXO) drift from Active+Fee,
// and requires the new debit (sendAmount + true fee) to match the vault drop exactly.
func acct1Drift(t *testing.T, inputAmount, amount int64) (drift, estimate, trueFee int64, change int) {
	t.Helper()
	net := &chaincfg.RegressionNetParams
	p, b := pk(0x51), pk(0x52)
	cs := &ContractState{
		NetworkParams: net,
		Supply:        SystemSupply{BaseFeeRate: 2},
		Vaults:        VaultRegistry{{Generation: 0, Primary: p, Backup: b, Status: VaultStatusActive}},
		PublicKeys:    PublicKeys{Primary: p, Backup: b},
	}
	changeAddr, _, _ := createP2WSHAddressWithBackup(p, b, nil, net)
	dest, _, _ := createP2WSHAddressWithBackup(pk(0x61), pk(0x62), nil, net)
	in := &Utxo{TxId: testTxId64, Vout: 0, Amount: inputAmount, Generation: 0}
	const vscFee = 0 // VscFeeMinSats/VscFeeRateBps are 0 today
	utxoSel := amount - vscFee
	est, err := cs.estimateFee(1, utxoSel, inputAmount)
	if err != nil {
		t.Fatal(err)
	}
	send := utxoSel - est
	tx, _, fee, err := cs.buildSpendTransaction([]*Utxo{in}, inputAmount, dest, changeAddr, send)
	if err != nil {
		t.Fatal(err)
	}
	var changeTotal int64
	cAddr, _ := btcutil.DecodeAddress(changeAddr, net)
	cScript, err := txscript.PayToAddrScript(cAddr)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range tx.TxOut {
		if string(o.PkScript) == string(cScript) {
			changeTotal += o.Value
			change++
		}
	}
	oldDebit := utxoSel // before ACCT-1: Active -= amount, Fee += vscFee
	vaultDrop := inputAmount - changeTotal
	newDebit := send + fee // ACCT-1: vscFee + sendAmount + true fee
	if newDebit != vaultDrop {
		t.Fatalf("new debit %d != vault drop %d", newDebit, vaultDrop)
	}
	return oldDebit - vaultDrop, est, fee, change
}

func TestAcct1_DeductFeeDriftBothWays(t *testing.T) {
	// With a change output the estimate exceeds the true fee: the vault keeps a
	// surplus no supply bucket counts (Σ > Active+Fee).
	d, est, fee, ch := acct1Drift(t, 100_000, 50_000)
	t.Logf("with change: estimate %d, true fee %d, change outputs %d, drift %+d sats", est, fee, ch, d)
	if ch == 0 || d <= 0 {
		t.Fatalf("expected a change output and a positive drift, got change=%d drift=%d", ch, d)
	}
	// Sub-dust change is burned to the miner: the vault loses the whole input while
	// the user was charged only `amount`, so Σ < Active+Fee (under-backed).
	d, est, fee, ch = acct1Drift(t, 50_300, 50_000)
	t.Logf("no change:   estimate %d, true fee %d, change outputs %d, drift %+d sats", est, fee, ch, d)
	if ch != 0 || d >= 0 {
		t.Fatalf("expected no change output and a negative drift, got change=%d drift=%d", ch, d)
	}
}
