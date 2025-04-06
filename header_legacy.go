package ethtypes

import (
	"errors"
	"math/big"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/keccak"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var ErrNilProtoHeader = errors.New("proto header is nil")

var _ headerData = (*HeaderLegacy)(nil)

// HeaderLegacy represents the legacy header type (pre EIP-1559)
type HeaderLegacy struct {
	ExtraData        []byte  // Extra data field, often used for creator-encoded information
	LogsBloom        Bloom   // Bloom filter for quick searching of logs in the block
	ParentHash       Hash    // Hash of the previous block (the parent block)
	UncleHash        Hash    // Hash of the uncles block list
	StateRoot        Hash    // Root of the state trie (Ethereum state at the end of this block)
	TransactionsRoot Hash    // Root of the transactions trie (all transactions for this block)
	ReceiptsRoot     Hash    // Root of the receipts trie (all transaction receipts for this block)
	MixDigest        Hash    // Hash used in the proof-of-work algorithm (before Ethereum 2.0)
	Coinbase         Address // Address of the block creator
	Difficulty       uint64  // The difficulty of mining the block
	Number           uint64  // The block number (height of the block in the chain)
	GasLimit         uint64  // Gas limit for the block
	GasUsed          uint64  // Total gas used by all transactions in the block
	Nonce            uint64  // Random value used by the miner in proof-of-work (before Ethereum 2.0)
	Timestamp        int64   // Timestamp when the block was created
}

func (h *HeaderLegacy) getHash() Hash {
	return BytesToHash(h.SignaturePayload())
}

func (h *HeaderLegacy) getParentHash() Hash {
	return h.ParentHash
}

func (h *HeaderLegacy) getUncleHash() Hash {
	return h.UncleHash
}

func (h *HeaderLegacy) getStateRoot() Hash {
	return h.StateRoot
}

func (h *HeaderLegacy) getTransactionsRoot() Hash {
	return h.TransactionsRoot
}

func (h *HeaderLegacy) getReceiptsRoot() Hash {
	return h.ReceiptsRoot
}

func (h *HeaderLegacy) getMixDigest() Hash {
	return h.MixDigest
}

func (h *HeaderLegacy) getCoinbase() Address {
	return h.Coinbase
}

func (h *HeaderLegacy) getLogsBloom() Bloom {
	return h.LogsBloom
}

func (h *HeaderLegacy) getExtraData() []byte {
	return h.ExtraData
}

func (h *HeaderLegacy) getDifficulty() uint64 {
	return h.Difficulty
}

func (h *HeaderLegacy) getNumber() uint64 {
	return h.Number
}

func (h *HeaderLegacy) getGasLimit() uint64 {
	return h.GasLimit
}

func (h *HeaderLegacy) getGasUsed() uint64 {
	return h.GasUsed
}

func (h *HeaderLegacy) getTimestamp() int64 {
	return h.Timestamp
}

func (h *HeaderLegacy) getNonce() uint64 {
	return h.Nonce
}

func (h *HeaderLegacy) getBaseFeePerGas() *big.Int {
	return big.NewInt(0) // No base fee per gas
}

func (h *HeaderLegacy) getWithdrawalsRoot() Hash {
	return ZeroStorageHash // no withdrawals root
}

// SignaturePayload constructs the legacy header signature payload.
// The signature payload (what's being signed) is the keccak of a specific RLP encoding.
//
// RLP structure that needs to be constructed and keccak-ed later:
//
//   - RLP: [parentHash, unclesHash, coinbase, stateRoot, transactionsRoot,
//     receiptsRoot, logsBloom, difficulty, number, gasLimit, gasUsed, timestamp, extraData, mixHash, nonce]
func (h *HeaderLegacy) SignaturePayload() []byte {
	// Construct the RLP data
	rlpPayload := [][]byte{
		ethrlp.EncodeBytes(h.ParentHash.ToBytes()),
		ethrlp.EncodeBytes(h.UncleHash.ToBytes()),
		ethrlp.EncodeBytes(h.Coinbase.ToBytes()),
		ethrlp.EncodeBytes(h.StateRoot.ToBytes()),
		ethrlp.EncodeBytes(h.TransactionsRoot.ToBytes()),
		ethrlp.EncodeBytes(h.ReceiptsRoot.ToBytes()),
		ethrlp.EncodeBytes(h.LogsBloom.ToBytes()),
		ethrlp.EncodeUint(h.Difficulty),
		ethrlp.EncodeUint(h.Number),
		ethrlp.EncodeUint(h.GasLimit),
		ethrlp.EncodeUint(h.GasUsed),
		ethrlp.EncodeInt(h.Timestamp),
		ethrlp.EncodeBytes(h.ExtraData),
		ethrlp.EncodeBytes(h.MixDigest.ToBytes()),
		ethrlp.EncodeUint(h.Nonce),
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Keccak the RLP encoding
	return keccak.New().Hash(rlpEncoding)
}

// FromProto converts a protobuf Header to a legacy header
func (h *HeaderLegacy) FromProto(pb *ethProto.Header) error {
	if pb == nil {
		return ErrNilProtoHeader
	}

	// Convert fixed fields
	h.ParentHash = BytesToHash(pb.ParentHash)
	h.UncleHash = BytesToHash(pb.UnclesHash)
	h.StateRoot = BytesToHash(pb.StateRoot)
	h.TransactionsRoot = BytesToHash(pb.TransactionsRoot)
	h.ReceiptsRoot = BytesToHash(pb.ReceiptsRoot)
	h.MixDigest = BytesToHash(pb.MixDigest)
	h.Coinbase = BytesToAddress(pb.Coinbase)
	h.LogsBloom = BytesToBloom(pb.LogsBloom)
	h.ExtraData = pb.ExtraData
	h.Difficulty = pb.Difficulty
	h.Number = pb.Number
	h.GasLimit = pb.GasLimit
	h.GasUsed = pb.GasUsed
	h.Timestamp = pb.Timestamp
	h.Nonce = pb.Nonce

	// Since this is a legacy header, payload fields are ignored
	return nil
}

// ToProto converts a legacy header proto to a protobuf Header
func (h *HeaderLegacy) ToProto() *ethProto.Header {
	pb := &ethProto.Header{
		ParentHash:       h.ParentHash.ToBytes(),
		UnclesHash:       h.UncleHash.ToBytes(),
		StateRoot:        h.StateRoot.ToBytes(),
		TransactionsRoot: h.TransactionsRoot.ToBytes(),
		ReceiptsRoot:     h.ReceiptsRoot.ToBytes(),
		MixDigest:        h.MixDigest.ToBytes(),
		Coinbase:         h.Coinbase.ToBytes(),
		LogsBloom:        h.LogsBloom.ToBytes(),
		ExtraData:        h.ExtraData,
		Difficulty:       h.Difficulty,
		Number:           h.Number,
		GasLimit:         h.GasLimit,
		GasUsed:          h.GasUsed,
		Timestamp:        h.Timestamp,
		Nonce:            h.Nonce,
	}

	// Since this is a legacy header, payload fields are ignored
	return pb
}
