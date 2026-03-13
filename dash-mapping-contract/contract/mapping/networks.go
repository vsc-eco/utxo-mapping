package mapping

import (
	"strings"

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

type VscNetwork struct {
	validPrefixes []string
}

func (v *VscNetwork) Name() NetworkName {
	return Vsc
}

func (v *VscNetwork) ValidateAddress(address string) bool {
	for _, prefix := range v.validPrefixes {
		if strings.HasPrefix(address, prefix) {
			return true
		}
	}
	return false
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
		Vsc: &VscNetwork{
			validPrefixes: []string{"hive:", "did:"},
		},
		Dash: &DashNetwork{
			networkParams: networkParams,
		},
	}
}
