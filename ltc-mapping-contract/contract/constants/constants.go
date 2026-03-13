package constants

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

const OracleAddress = "did:vsc:oracle:ltc"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "block/"

const (
	Testnet string = "testnet"
	Mainnet string = "mainnet"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet
}
