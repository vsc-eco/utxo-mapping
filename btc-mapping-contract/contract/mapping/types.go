package mapping

import (
	"net/url"

	"github.com/btcsuite/btcd/chaincfg"
)

//tinyjson:json
type MapParams struct {
	TxData *VerificationRequest `json:"tx_data"`
	// strings should be valid URL search params, to be decoded later
	Instructions []string `json:"instructions"`
}

//tinyjson:json
type VerificationRequest struct {
	BlockHeight    uint32 `json:"block_height"`
	RawTxHex       string `json:"raw_tx_hex"`
	MerkleProofHex string `json:"merkle_proof_hex"` // array of byte arrays, each of which is guaranteed 32 bytes
	TxIndex        uint32 `json:"tx_index"`         // position of the tx in the block
}

type Deposit struct {
	to     string
	from   string
	amount int64
}

//tinyjson:json
type AccountInfo struct {
	ModifiedAt uint64 // hive block height
	Address    string // Caip10address (bitcoin address they can recieve funds at)
}

// address should be Magi for internal transfers and BTC for unmaps
//
//tinyjson:json
type TransferParams struct {
	Amount    string `json:"amount"`
	To        string `json:"to"`
	From      string `json:"from,omitempty"`
	DeductFee bool   `json:"deduct_fee,omitempty"`
	MaxFee    *int64 `json:"max_fee,omitempty"`
}

// Utxo stores full UTXO data indexed by a single-byte pool ID.
// Serialised to binary (not JSON) via MarshalUtxo/UnmarshalUtxo.
// Tag is raw bytes (SHA-256 of the instruction string), not hex.
type Utxo struct {
	TxId     string // display-hex txid (64 chars)
	Vout     uint32
	Amount   int64
	PkScript []byte
	Tag      []byte // raw tag bytes (32 bytes for deposits, empty for change)
	// Generation is the vault generation whose address locked this UTXO (S1 dual-gen).
	// Appended to the blob; pre-S1 blobs lack it and read as 0 (all pre-existing
	// UTXOs belong to generation 0). Used at spend time to pick the right gen's
	// pubkey + keyId for the witness/signature.
	Generation uint32
}

// UtxoRegistryEntry holds a uint16 pool ID and a 6-byte amount for one UTXO.
//
// Binary layout of the registry ("r" state key): each entry is 8 bytes.
//   - Bytes 0–1: ID (uint16 BE; 0–1023 = unconfirmed, 1024–65535 = confirmed)
//   - Bytes 2–7: Amount in satoshis (uint48 BE, max ~2.81M BTC)
type UtxoRegistryEntry struct {
	Id     uint16 // 0-1023 = unconfirmed, 1024-65535 = confirmed
	Amount int64
}

// UtxoRegistry is the in-memory UTXO list, serialised as packed binary.
type UtxoRegistry []UtxoRegistryEntry

// VaultStatus is the lifecycle state of a vault generation (S1-DESIGN.md §3).
// S1 drives PENDING→ACTIVE→RETIRING; S2/S5 drive DRAINING→INACTIVE→PURGED.
type VaultStatus uint8

const (
	VaultStatusPending  VaultStatus = 0
	VaultStatusActive   VaultStatus = 1
	VaultStatusRetiring VaultStatus = 2
	VaultStatusDraining VaultStatus = 3
	VaultStatusInactive VaultStatus = 4
	VaultStatusPurged   VaultStatus = 5
)

// VaultEntrySize is the fixed packed-binary width of one Vault entry in the "v"
// registry blob: 4 gen + 33 primary + 33 backup + 1 status + 4 predecessor +
// 4*4 heights = 91 bytes.
//
// SCHEMA NOTE (S5): grew 87→91 to carry InactiveHeight (the DRAINING→INACTIVE
// grace anchor). Safe: the "v" registry is S1 rotation machinery, never written
// on any deployed (mainnet) contract — this whole branch is pre-pin and inert
// behind the node deploy gate, so there is no live 87-byte blob to migrate.
// Marshal/Unmarshal (utils.go) MUST move in lock-step with this constant.
const VaultEntrySize = 91

// Vault is one generation of the BTC vault key set. Vaults form an append-only
// list (state key "v"): minting a generation appends a PENDING entry; existing
// entries only STATUS-transition — their pubkeys are NEVER mutated, preserving
// the mainnet key-immutability property. See S1-DESIGN.md.
//
// Binary layout (VaultEntrySize = 91 bytes/entry, big-endian):
//
//	[0:4]   Generation
//	[4:37]  Primary  (33-byte compressed pubkey)
//	[37:70] Backup   (33-byte compressed pubkey)
//	[70]    Status
//	[71:75] Predecessor      (generation this one succeeds; gen 0 = 0)
//	[75:79] CreatedHeight
//	[79:83] ActivatedHeight
//	[83:87] RetiredHeight    (BTC height it went ACTIVE→RETIRING)
//	[87:91] InactiveHeight   (BTC height it went DRAINING→INACTIVE; S5 purge-grace anchor, 0 until then)
type Vault struct {
	Generation      uint32
	Primary         CompressedPubKey
	Backup          CompressedPubKey
	Status          VaultStatus
	Predecessor     uint32
	CreatedHeight   uint32
	ActivatedHeight uint32
	RetiredHeight   uint32
	// InactiveHeight is the BTC block height at which this gen was reconciled
	// DRAINING→INACTIVE (registry-empty). It is the anchor for the purge grace
	// (Inactive→Purged requires height ≥ InactiveHeight + VaultPurgeGraceBlocks).
	// 0 for any gen that has not been reconciled to INACTIVE — and a 0 value is a
	// hard fail-closed guard in the purge gate (never purge a gen with no anchor).
	InactiveHeight uint32
}

// VaultRegistry is the in-memory append-only vault-generation list, serialised as
// packed binary (state key "v").
type VaultRegistry []Vault

// TxSpendsRegistry is the in-memory list of pending spend-tx IDs (display hex).
// Serialised as packed binary: 32 raw bytes per entry.
type TxSpendsRegistry []string

// MigrationSweep is the per-sweep record (state key "ms-"+txId) that BRK-1's
// delete-at-confirm migration writes at BUILD and settles+deletes at CONFIRM. It
// carries exactly what the confirm-side atomic swap needs: the input UTXO ids to
// delete, the reserved miner fee to debit, and the successor address+generation to
// index the swept output(s) to. Trusted at confirm (not re-derived): the SPV-proven
// txid commits to the outputs, so the tx provably pays SuccessorAddress and its output
// must carry the build-time SuccessorGen to be spendable. Hand-packed binary
// (MarshalMigrationSweep); SuccessorAddress is the record tail (no length prefix).
type MigrationSweep struct {
	InputIds         []uint16
	BtcFee           int64
	SuccessorAddress string
	SuccessorGen     uint32
	// BuildHeight (L7-01) is the LastHeight at which this sweep tx was built — the
	// deterministic clock for the re-drive staleness gate (RedriveStaleBlocks). 0 on a
	// legacy record predating L7-01 (this whole version is unreleased, so none exist).
	BuildHeight uint32
}

// PendingUnmap is the per-unmap record (state key "us-"+txId) that Guard 1's
// delete-at-confirm withdrawal path writes at BUILD and settles+deletes at CONFIRM. It
// carries exactly what settleUnmap needs: the input UTXO ids to delete (kept registered +
// reserved since build) and the change ADDRESS + GENERATION to index the confirmed change
// output(s) to. No fee/amount field is stored — conservation is guaranteed by the
// build-time balance debit plus BIP143 (the SPV-proven tx's inputs equal their registry
// amounts), so no settle-time fee-equality assert is used (it would brick a legitimate
// no-change / dust-burn unmap whose real fee exceeds any recorded estimate). ChangeGen (not
// re-derived at confirm) keeps the change spendable if the vault rotated between build and
// confirm. Hand-packed binary (MarshalPendingUnmap); ChangeAddress is the record tail.
type PendingUnmap struct {
	InputIds      []uint16
	ChangeAddress string
	ChangeGen     uint32
	// BtcFee (L7-01) is the miner fee THIS unmap tx pays (build-time true fee, or a
	// re-driven replacement's bumped fee). Stored so a re-drive can compute the fee
	// delta and so settle can refund the unused re-drive charge back to FeeSupply. It is
	// NOT used for a settle-time fee-equality assert (that would brick a legitimate
	// no-change / dust-burn unmap — see settleUnmap).
	BtcFee int64
	// BuildHeight (L7-01) — see MigrationSweep.BuildHeight (the re-drive staleness clock).
	BuildHeight uint32
}

// SpendGroup (state key "g-"+<minInputId>) is the L7-01 re-drive spend group: the txids
// that all spend the identical reserved input set (original + RBF replacements), plus the
// HIGHEST fee committed across the group. Written lazily on the first re-drive; absent ⇒ a
// group-of-one. HighestFee tracks how much FeeSupply the re-drives have charged for the
// bump so settle can refund the unused portion when a CHEAPER member (e.g. the original)
// confirms instead of the priciest replacement. Hand-packed binary (MarshalSpendGroup).
type SpendGroup struct {
	Members    []string // txids (64-char hex), each with a live "us-"/"ms-" record
	HighestFee int64    // max BtcFee committed across Members (the FeeSupply charge basis)
}

type MappingType string

const (
	MapDeposit MappingType = "deposit"
	MapSwap    MappingType = "swap"
)

type NetworkName string

type AddressMetadata struct {
	Instruction string
	Params      *url.Values // instruction that is hashed to the tag used to create the address
	Recipient   string
	OutNetwork  NetworkName
	Tag         []byte // tag (hashed instruction) used to create the address
	Type        MappingType
	// Generation is the vault generation whose keys derived this deposit address.
	// A deposit indexed at this address is tagged with it (S1.3 C-1 / S1.4) so the
	// spend path later resolves the correct per-generation witness keys + TSS keyId.
	// S1.4: the registry holds an address for EVERY fund-holding generation, each
	// entry carrying its own Generation, so a late deposit to a superseded gen credits.
	Generation uint32
}

// SystemSupply tracks protocol-wide BTC accounting.
// Serialised as 32 raw bytes: four int64 values in little-endian order.
//
// Binary layout ("sply" state key):
//   - Bytes  0– 7: ActiveSupply
//   - Bytes  8–15: UserSupply
//   - Bytes 16–23: FeeSupply
//   - Bytes 24–31: BaseFeeRate (sats per byte)
type SystemSupply struct {
	ActiveSupply int64
	UserSupply   int64
	FeeSupply    int64
	BaseFeeRate  int64 // sats per byte
}

// ContractState is the top-level in-memory state loaded at the start of each
// contract action and saved at the end.
//
// ConfirmedNextId and UnconfirmedNextId are stored together as 4 bytes at "i":
// two uint16 BE values [confirmedNext, unconfirmedNext].
type ContractState struct {
	// MinConfirmations is how deep an L1 event must be before the contract acts on
	// it as final — crediting a deposit (VR2-07) or settling a spend (VR2-06).
	// Resolved from the build's network at construction and carried here rather
	// than re-derived at each call site, so there is exactly one place it can be
	// wrong and both gates cannot drift apart.
	MinConfirmations  uint32
	UtxoList          UtxoRegistry
	ConfirmedNextId   uint16 // next candidate in the confirmed pool   (1024–65535, wraps)
	UnconfirmedNextId uint16 // next candidate in the unconfirmed pool (0–1023,    wraps)
	TxSpendsList      TxSpendsRegistry
	// MigrationSweeps is the dedicated list of pending migration-sweep txids (BRK-1
	// council A-1). It is a strict subset of TxSpendsList (every migration sweep is also a
	// pending spend), maintained by the owner-only migrateVault path so pendingMigrationState
	// scans only the handful of in-flight sweeps rather than the unbounded, unprivileged-
	// inflatable TxSpendsList. Same packed-txid encoding as TxSpendsList.
	MigrationSweeps TxSpendsRegistry
	Supply          SystemSupply
	PublicKeys      PublicKeys
	NetworkParams   *chaincfg.Params

	// S1 dual-generation vault state model (empty until the gen-0 fold migration).
	Vaults    VaultRegistry
	NextGen   uint32 // next generation number to mint
	ActiveGen uint32 // generation currently receiving new deposits
}

type MappingState struct {
	ContractState
	AddressRegistry map[string]*AddressMetadata // map of btc addresses to the tags they were created with
}

// DEX Instruction Schema
//
//tinyjson:json
type DexInstruction struct {
	Type             string            `json:"type"`
	Version          string            `json:"version"`
	AssetIn          string            `json:"asset_in"`
	AssetOut         string            `json:"asset_out"`
	Recipient        string            `json:"recipient"`
	MinAmountOut     *string           `json:"min_amount_out,omitempty"`
	Beneficiary      *string           `json:"beneficiary,omitempty"`
	RefBps           *uint64           `json:"ref_bps,omitempty"`
	ReturnAddress    *ReturnAddress    `json:"return_address,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	AmountIn         string            `json:"amount_in"`
	DestinationChain string            `json:"destination_chain,omitempty"`
}

//tinyjson:json
type PoolInfo struct {
	Asset0   string `json:"asset0"`
	Asset1   string `json:"asset1"`
	Reserve0 string `json:"reserve0"`
	Reserve1 string `json:"reserve1"`
	Fee      uint64 `json:"fee"`
	TotalLp  string `json:"total_lp"`
}

//tinyjson:json
type SwapResult struct {
	AmountOut string   `json:"amount_out"`
	PoolState PoolInfo `json:"pool_state"` // Current pool state after swap
}

type ReturnAddress struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

const BtcAssetValue string = "BTC"

//tinyjson:json
type RegisterKeyParams struct {
	PrimaryPubKey string `json:"primary_public_key,omitempty"`
	BackupPubKey  string `json:"backup_public_key,omitempty"`
}

// CompressedPubKey is a 33-byte SEC1 compressed secp256k1 public key.
type CompressedPubKey [33]byte

type PublicKeys struct {
	Primary CompressedPubKey
	Backup  CompressedPubKey
}

//tinyjson:json
type RouterContract struct {
	ContractId string `json:"router_contract"`
}

//tinyjson:json
type AllowanceParams struct {
	Spender string `json:"spender"`
	Amount  string `json:"amount"`
}

//tinyjson:json
type ConfirmSpendParams struct {
	TxData  *VerificationRequest `json:"tx_data"`
	Indices []uint32             `json:"indices"`
}
