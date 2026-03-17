package constants

const DirPathDelimiter = "/"

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

const AllowancePrefix = "q" + DirPathDelimiter

const OracleAddress = "did:vsc:oracle:dash"
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
