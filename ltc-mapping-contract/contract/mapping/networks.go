package mapping

import (
	"ltc-mapping-contract/sdk"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

type Network interface {
	Name() NetworkName
	ValidateAddress(address string) bool
}

const (
	Ltc  NetworkName = "ltc"
	Vsc  NetworkName = "vsc"
	Hive NetworkName = "hive"
)

type VscNetwork struct{}

func (v *VscNetwork) Name() NetworkName {
	return Vsc
}

// ValidateAddress uses the SDK's Address.IsValid() method which validates
// all supported VSC address types (hive:, did:key:, did:pkh:eip155, contract:, system:).
func (v *VscNetwork) ValidateAddress(address string) bool {
	return sdk.Address(address).IsValid()
}

type LtcNetwork struct {
	networkParams *chaincfg.Params
}

func (b *LtcNetwork) Name() NetworkName {
	return Ltc
}

func (b *LtcNetwork) ValidateAddress(address string) bool {
	_, err := btcutil.DecodeAddress(address, b.networkParams)
	return err == nil
}

func initNetworkLookup(networkParams *chaincfg.Params) map[NetworkName]Network {
	return map[NetworkName]Network{
		Vsc: &VscNetwork{},
		Ltc: &LtcNetwork{
			networkParams: networkParams,
		},
	}
}
