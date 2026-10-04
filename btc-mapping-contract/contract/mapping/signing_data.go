package mapping

//go:generate msgp
type SigningData struct {
	Tx                []byte            `msg:"tx"`
	UnsignedSigHashes []UnsignedSigHash `msg:"uh"`
}

type UnsignedSigHash struct {
	Index         uint32 `msg:"i"`
	SigHash       []byte `msg:"hs"`
	WitnessScript []byte `msg:"ws"`
	// Amount is the spent input's value in satoshis. Carried so the go-vsc-node
	// TSS layer can INDEPENDENTLY recompute this input's BIP143 (segwit-v0)
	// sighash and confirm it equals what it is being asked to sign, before a
	// retiring-generation key contributes a share (S3 non-negotiable #1,
	// output-scoped signing). A lied amount cannot match the real sighash, so
	// the node fails closed — never a theft. Optional on the wire (msgp map):
	// pre-S3 blobs omit it and decode as 0.
	Amount int64 `msg:"am"`
}
