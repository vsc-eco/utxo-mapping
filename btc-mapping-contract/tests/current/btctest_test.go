package current_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"testing"
	"time"

	"btc-mapping-contract/contract/mapping"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Well-known secp256k1 test vectors: private keys 1 and 2.
const (
	TestPrimaryPubKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	TestBackupPubKeyHex  = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)

func regtestParams() *chaincfg.Params {
	return &chaincfg.RegressionNetParams
}

// encodeBalance encodes amount using the same compact big-endian binary
// format as setAccBal, so the value can be seeded directly into contract state.
func encodeBalance(t *testing.T, amount int64) string {
	t.Helper()
	if amount == 0 {
		return ""
	}
	v := uint64(amount)
	n := (bits.Len64(v) + 7) / 8
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return string(buf[8-n:])
}

// encodeUtxoCounters encodes the confirmed and unconfirmed next-ID cursors
// into the 4-byte format expected by the contract (two uint16 BE values).
func encodeUtxoCounters(confirmedNext, unconfirmedNext uint16) string {
	var buf [4]byte
	binary.BigEndian.PutUint16(buf[0:], confirmedNext)
	binary.BigEndian.PutUint16(buf[2:], unconfirmedNext)
	return string(buf[:])
}

// decodeHex decodes a hex string to raw bytes as a string, for state seeding.
func decodeHex(t *testing.T, s string) string {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("decodeHex failed:", err)
	}
	return string(b)
}

// regtestDestAddress returns a P2WPKH address derived from TestBackupPubKeyHex
// on the regtest network (bcrt1q...).
func regtestDestAddress(t *testing.T) string {
	t.Helper()
	pubKeyBytes, err := hex.DecodeString(TestBackupPubKeyHex)
	if err != nil {
		t.Fatal("invalid test backup public key hex:", err)
	}
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKeyBytes),
		regtestParams(),
	)
	if err != nil {
		t.Fatal("failed to create regtest dest address:", err)
	}
	return addr.EncodeAddress()
}

// buildRegtestHeader creates a valid regtest block header by mining for a nonce
// that satisfies the compact target 0x207fffff (hash must be ≤ 7fffff000...0).
// On average this needs ~2 iterations since ~50% of random hashes pass.
func buildRegtestHeader(prevBlock, merkleRoot chainhash.Hash, ts time.Time) *wire.BlockHeader {
	h := &wire.BlockHeader{
		Version:    1,
		PrevBlock:  prevBlock,
		MerkleRoot: merkleRoot,
		Timestamp:  ts,
		Bits:       0x207fffff,
		Nonce:      0,
	}
	target := blockchain.CompactToBig(0x207fffff)
	for {
		hash := h.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			return h
		}
		h.Nonce++
	}
}

// serializeHeader serializes a block header to 80-byte hex.
func serializeHeader(t *testing.T, h *wire.BlockHeader) string {
	t.Helper()
	var buf bytes.Buffer
	if err := h.Serialize(&buf); err != nil {
		t.Fatal("failed to serialize block header:", err)
	}
	return hex.EncodeToString(buf.Bytes())
}

// serializeHeaderRaw serializes a block header to raw 80 bytes as a string,
// suitable for seeding directly into contract state.
func serializeHeaderRaw(t *testing.T, h *wire.BlockHeader) string {
	t.Helper()
	var buf bytes.Buffer
	if err := h.Serialize(&buf); err != nil {
		t.Fatal("failed to serialize block header:", err)
	}
	return buf.String()
}

// buildTestTx creates a minimal transaction paying amount sats to toAddress.
// The contract only checks the Merkle proof, not the transaction inputs.
func buildTestTx(t *testing.T, toAddress string, amount int64) *wire.MsgTx {
	t.Helper()
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0xffffffff},
		SignatureScript:  []byte{0x00},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	addr, err := btcutil.DecodeAddress(toAddress, regtestParams())
	if err != nil {
		t.Fatal("failed to decode address:", err)
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal("failed to create output script:", err)
	}
	tx.AddTxOut(&wire.TxOut{Value: amount, PkScript: script})
	return tx
}

// serializeTx serializes a transaction to hex.
func serializeTx(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatal("failed to serialize tx:", err)
	}
	return hex.EncodeToString(buf.Bytes())
}

// depositUtxoBinary builds a binary-encoded Utxo for a UTXO produced by a deposit
// instruction. The PkScript and Tag are derived from the instruction string,
// matching the on-chain address derivation.
func depositUtxoBinary(t *testing.T, txId string, vout uint32, amount int64, instruction string) string {
	t.Helper()
	address, _, err := mapping.DepositAddress(TestPrimaryPubKeyHex, TestBackupPubKeyHex, instruction, regtestParams())
	if err != nil {
		t.Fatal("failed to derive deposit address:", err)
	}
	addr, err := btcutil.DecodeAddress(address, regtestParams())
	if err != nil {
		t.Fatal("failed to decode deposit address:", err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal("failed to create pkscript:", err)
	}
	sum := sha256.Sum256([]byte(instruction))
	utxo := mapping.Utxo{
		TxId:     txId,
		Vout:     vout,
		Amount:   amount,
		PkScript: pkScript,
		Tag:      sum[:],
	}
	return string(mapping.MarshalUtxo(&utxo))
}

// changeUtxoBinary builds a binary-encoded Utxo for a change UTXO (nil tag),
// matching the change address derivation used by HandleUnmap.
func changeUtxoBinary(t *testing.T, txId string, vout uint32, amount int64) string {
	t.Helper()
	// nil tag → change address path (OP_CHECKSIGVERIFY + OP_DATA_0)
	address, _, err := mapping.AddressWithBackup(TestPrimaryPubKeyHex, TestBackupPubKeyHex, nil, regtestParams())
	if err != nil {
		t.Fatal("failed to derive change address:", err)
	}
	addr, err := btcutil.DecodeAddress(address, regtestParams())
	if err != nil {
		t.Fatal("failed to decode change address:", err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal("failed to create pkscript:", err)
	}
	utxo := mapping.Utxo{
		TxId:     txId,
		Vout:     vout,
		Amount:   amount,
		PkScript: pkScript,
		Tag:      nil,
	}
	return string(mapping.MarshalUtxo(&utxo))
}

// MapTestFixture holds all data needed to call the map contract action.
type MapTestFixture struct {
	RawTxHex       string
	BlockHeaderHex string // hex-encoded, for use in VerificationRequest
	MerkleProofHex string
	TxIndex        uint32
	BlockHeight    uint32
}

// buildMapFixture creates a transaction paying to the deposit address for the
// given instruction, then wraps it in a single-tx block (MerkleRoot = TxHash,
// empty proof, TxIndex = 0) so the on-chain Merkle verification trivially passes.
func buildMapFixture(t *testing.T, instruction string, amount int64, blockHeight uint32) MapTestFixture {
	t.Helper()
	address, _, err := mapping.DepositAddress(TestPrimaryPubKeyHex, TestBackupPubKeyHex, instruction, regtestParams())
	if err != nil {
		t.Fatal("failed to derive deposit address:", err)
	}
	tx := buildTestTx(t, address, amount)
	txHash := tx.TxHash()
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	header := buildRegtestHeader(chainhash.Hash{}, txHash, ts)
	return MapTestFixture{
		RawTxHex:       serializeTx(t, tx),
		BlockHeaderHex: serializeHeader(t, header),
		MerkleProofHex: "",
		TxIndex:        0,
		BlockHeight:    blockHeight,
	}
}

// ConfirmSpendFixture holds all data needed to call the confirmSpend contract action.
type ConfirmSpendFixture struct {
	TxId           string
	RawTxHex       string
	MerkleProofHex string
	TxIndex        uint32
	BlockHeight    uint32
	BlockHeaderRaw string // raw bytes as string, for state seeding
}

// buildConfirmSpendFixture creates a minimal "spend tx" paying to the contract's
// change address, then wraps it in a single-tx block (MerkleRoot = TxHash,
// empty proof, TxIndex = 0) so the on-chain Merkle verification trivially passes.
func buildConfirmSpendFixture(t *testing.T, blockHeight uint32) ConfirmSpendFixture {
	t.Helper()
	changeAddr, _, err := mapping.AddressWithBackup(TestPrimaryPubKeyHex, TestBackupPubKeyHex, nil, regtestParams())
	if err != nil {
		t.Fatal("failed to derive change address:", err)
	}
	tx := buildTestTx(t, changeAddr, 2000)
	txHash := tx.TxHash()
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	header := buildRegtestHeader(chainhash.Hash{}, txHash, ts)
	return ConfirmSpendFixture{
		TxId:           tx.TxID(),
		RawTxHex:       serializeTx(t, tx),
		MerkleProofHex: "",
		TxIndex:        0,
		BlockHeight:    blockHeight,
		BlockHeaderRaw: serializeHeaderRaw(t, header),
	}
}

// buildSeedHeader creates a single standalone regtest block header (no prev
// block) serialized to hex, ready for use in SeedBlocksParams.BlockHeader.
func buildSeedHeader(t *testing.T, ts time.Time) string {
	t.Helper()
	header := buildRegtestHeader(chainhash.Hash{}, chainhash.Hash{}, ts)
	return serializeHeader(t, header)
}

// buildSeedHeaderRaw creates a seed header and returns raw bytes as a string,
// suitable for seeding directly into contract state.
func buildSeedHeaderRaw(t *testing.T, ts time.Time) string {
	t.Helper()
	header := buildRegtestHeader(chainhash.Hash{}, chainhash.Hash{}, ts)
	return serializeHeaderRaw(t, header)
}

// buildHeaderChain creates a seed header plus count chained headers.
// Each successive header has PrevBlock = previous header's hash and timestamp
// incremented by 10 minutes, keeping all timestamps within the 2-hour window
// required by CheckBlockHeaderSanity.
// Returns (seedHeaderHex, chainedHeadersHex) where chainedHeadersHex is all
// count headers concatenated, suitable for AddBlocksParams.Blocks.
func buildHeaderChain(t *testing.T, seedTime time.Time, count int) (string, string) {
	t.Helper()
	seed := buildRegtestHeader(chainhash.Hash{}, chainhash.Hash{}, seedTime)
	seedHex := serializeHeader(t, seed)

	var chainBuf bytes.Buffer
	prev := seed
	for i := 0; i < count; i++ {
		prevHash := prev.BlockHash()
		next := buildRegtestHeader(prevHash, chainhash.Hash{}, prev.Timestamp.Add(10*time.Minute))
		chainBuf.WriteString(serializeHeader(t, next))
		prev = next
	}
	return seedHex, chainBuf.String()
}
