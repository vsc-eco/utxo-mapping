package mapping

import (
	"dash-mapping-contract/sdk"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

type Network interface {
	Name() NetworkName
	ValidateAddress(address string) bool
}

const (
	Dash NetworkName = "dash"
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

type DashNetwork struct {
	networkParams *chaincfg.Params
}

func (b *DashNetwork) Name() NetworkName {
	return Dash
}

func (b *DashNetwork) ValidateAddress(address string) bool {
	_, err := btcutil.DecodeAddress(address, b.networkParams)
	return err == nil
}

func initNetworkLookup(networkParams *chaincfg.Params) map[NetworkName]Network {
	return map[NetworkName]Network{
		Vsc: &VscNetwork{},
		Dash: &DashNetwork{
			networkParams: networkParams,
		},
	}
}
