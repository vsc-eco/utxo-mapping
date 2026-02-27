package constants

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

const OracleAddress = "did:vsc:oracle:btc"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "block/"

const (
	Testnet3 string = "testnet3"
	Testnet4 string = "testnet4"
	Mainnet  string = "mainnet"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet3 || networkName == Testnet4
}
