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
	Btc  NetworkName = "btc"
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

type BtcNetwork struct {
	networkParams *chaincfg.Params
}

func (b *BtcNetwork) Name() NetworkName {
	return Btc
}

func (b *BtcNetwork) ValidateAddress(address string) bool {
	_, err := btcutil.DecodeAddress(address, b.networkParams)
	return err == nil
}

func initNetworkLookup(networkParams *chaincfg.Params) map[NetworkName]Network {
	return map[NetworkName]Network{
		Vsc: &VscNetwork{
			validPrefixes: []string{"hive:", "did:"},
		},
		Btc: &BtcNetwork{
			networkParams: networkParams,
		},
	}
}
