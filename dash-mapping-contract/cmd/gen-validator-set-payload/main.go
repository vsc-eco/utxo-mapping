// gen-validator-set-payload composes the SetValidatorSet admin payload
// from one or more announcer-format triples. Round-5 audit R5-DRIFT-04:
// the SetValidatorSet docstring promised a helper that didn't exist,
// forcing operators to hand-assemble the 4-field per-entry wire form.
//
// Usage:
//
//	gen-validator-set-payload -epoch 42 \
//	    -entry did:key:bls:z...,<pk_hex_96>,<pop_base64_raw_url>,<account> \
//	    -entry did:key:bls:z...,<pk_hex_96>,<pop_base64_raw_url>,<account>
//
// The PoP input is base64-RawURL (the form dids.GenerateBlsPoP returns);
// this tool decodes to raw bytes and hex-encodes them to match the
// contract verifier's input format. Output is the exact payload string
// to pass to SetValidatorSet:
//
//	<epoch>;<did>=<pk>=<pop_hex>=<account>|<did>=<pk>=<pop_hex>=<account>
//
// Round-5 audit R5-DRIFT-04 + round-4 audit R4-CSM-01.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var epoch uint64
	var entries stringSlice
	flag.Uint64Var(&epoch, "epoch", 0, "validator-set epoch (uint64)")
	flag.Var(&entries, "entry",
		"validator entry as did,pk_hex,pop_base64_rawurl,account (repeatable)")
	flag.Parse()

	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "at least one -entry is required")
		flag.Usage()
		os.Exit(2)
	}

	parts := make([]string, 0, len(entries))
	for i, raw := range entries {
		fields := strings.Split(raw, ",")
		if len(fields) != 4 {
			fmt.Fprintf(os.Stderr,
				"entry #%d: expected 4 comma-separated fields (did,pk,pop_b64,account); got %d\n",
				i+1, len(fields))
			os.Exit(2)
		}
		did, pkHex, popB64, account := fields[0], fields[1], fields[2], fields[3]
		if did == "" || pkHex == "" || popB64 == "" || account == "" {
			fmt.Fprintf(os.Stderr, "entry #%d has empty field(s)\n", i+1)
			os.Exit(2)
		}
		if len(pkHex) != 96 {
			fmt.Fprintf(os.Stderr,
				"entry #%d: pk must be 96 hex chars (48-byte compressed G1), got %d\n",
				i+1, len(pkHex))
			os.Exit(2)
		}
		if _, err := hex.DecodeString(pkHex); err != nil {
			fmt.Fprintf(os.Stderr, "entry #%d: pk hex decode failed: %v\n", i+1, err)
			os.Exit(2)
		}
		raw, err := base64.RawURLEncoding.DecodeString(popB64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "entry #%d: pop base64 decode failed: %v\n", i+1, err)
			os.Exit(2)
		}
		if len(raw) != 96 {
			fmt.Fprintf(os.Stderr,
				"entry #%d: pop must be 96 raw bytes (BLS G2 sig), got %d\n",
				i+1, len(raw))
			os.Exit(2)
		}
		popHex := hex.EncodeToString(raw)
		parts = append(parts, did+"="+pkHex+"="+popHex+"="+account)
	}
	payload := strconv.FormatUint(epoch, 10) + ";" + strings.Join(parts, "|")
	fmt.Println(payload)
}
