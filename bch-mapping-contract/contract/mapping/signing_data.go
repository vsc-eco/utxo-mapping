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
}
