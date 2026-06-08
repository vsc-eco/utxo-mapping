package mapping

// review8 DX-H5 — the BTC deposit-swap built its DexInstruction without a
// MinAmountOut, so a depositor's slippage bound never reached the router and the
// ingress swap executed at any price (proven: min_amount_out:"-1" succeeded).
// buildSwapInstruction now forwards the instruction's min_amount_out param. The
// router/dex enforce the bound downstream (dex-contracts TestSwapSlippageProtection);
// this test pins the mapping-side contract — the param is parsed, forwarded, and
// serialized into the swap-instruction JSON the router receives.

import (
	"net/url"
	"strings"
	"testing"

	"github.com/CosmWasm/tinyjson"
)

func mustParse(t *testing.T, s string) *url.Values {
	t.Helper()
	v, err := url.ParseQuery(s)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", s, err)
	}
	return &v
}

func TestReview8_DXH5_MinAmountOutForwardedAndSerialized(t *testing.T) {
	// With min_amount_out present it is forwarded into the instruction and emitted
	// in the JSON the router receives.
	p := mustParse(t, "swap_to=user:alice&swap_asset_out=hbd&min_amount_out=90000")
	instr := buildSwapInstruction(p, "user:alice", "hbd", 100000)
	if instr.MinAmountOut == nil || *instr.MinAmountOut != "90000" {
		t.Fatalf("DX-H5: min_amount_out must be forwarded, got %v", instr.MinAmountOut)
	}
	js, err := tinyjson.Marshal(instr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"min_amount_out":"90000"`) {
		t.Fatalf("DX-H5: swap instruction JSON must carry the bound, got %s", js)
	}

	// Without it, the field is omitted (legacy behaviour preserved — no forced min).
	p2 := mustParse(t, "swap_to=user:alice&swap_asset_out=hbd")
	instr2 := buildSwapInstruction(p2, "user:alice", "hbd", 100000)
	if instr2.MinAmountOut != nil {
		t.Fatalf("no min_amount_out param must leave MinAmountOut nil, got %v", *instr2.MinAmountOut)
	}
	js2, _ := tinyjson.Marshal(instr2)
	if strings.Contains(string(js2), "min_amount_out") {
		t.Fatalf("omitted bound must not appear in JSON, got %s", js2)
	}
}
