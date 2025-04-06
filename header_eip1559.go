package ethtypes

import (
	"errors"
	"math/big"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/keccak"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var ErrInvalidHeaderPayload = errors.New("invalid header payload type")

var _ headerData = (*HeaderEIP1559)(nil)

// HeaderEIP1559 represents the EIP-1559 header,
// introduced as part of EIP-1559 (London hardfork)
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md
type HeaderEIP1559 struct {
	BaseFeePerGas    *big.Int // Base fee per gas unit for EIP-1559 blocks
	ExtraData        []byte   // Extra data field, often used for creator-encoded information
	LogsBloom        Bloom    // Bloom filter for quick searching of logs in the block
	ParentHash       Hash     // Hash of the previous block (the parent block)
	UncleHash        Hash     // Hash of the uncles block list
	StateRoot        Hash     // Root of the state trie (Ethereum state at the end of this block)
	TransactionsRoot Hash     // Root of the transactions trie (all transactions for this block)
	ReceiptsRoot     Hash     // Root of the receipts trie (all transaction receipts for this block)
	MixDigest        Hash     // Hash used in the proof-of-work algorithm (before Ethereum 2.0)
	Coinbase         Address  // Address of the block creator
	Difficulty       uint64   // The difficulty of mining the block
	Number           uint64   // The block number (height of the block in the chain)
	GasLimit         uint64   // Gas limit for the block
	GasUsed          uint64   // Total gas used by all transactions in the block
	Nonce            uint64   // Random value used by the miner in proof-of-work (before Ethereum 2.0)
	Timestamp        int64    // Timestamp when the block was created
}

func (h *HeaderEIP1559) getHash() Hash {
	return BytesToHash(h.SignaturePayload())
}

func (h *HeaderEIP1559) getParentHash() Hash {
	return h.ParentHash
}

func (h *HeaderEIP1559) getUncleHash() Hash {
	return h.UncleHash
}

func (h *HeaderEIP1559) getStateRoot() Hash {
	return h.StateRoot
}

func (h *HeaderEIP1559) getTransactionsRoot() Hash {
	return h.TransactionsRoot
}

func (h *HeaderEIP1559) getReceiptsRoot() Hash {
	return h.ReceiptsRoot
}

func (h *HeaderEIP1559) getMixDigest() Hash {
	return h.MixDigest
}

func (h *HeaderEIP1559) getCoinbase() Address {
	return h.Coinbase
}

func (h *HeaderEIP1559) getLogsBloom() Bloom {
	return h.LogsBloom
}

func (h *HeaderEIP1559) getExtraData() []byte {
	return h.ExtraData
}

func (h *HeaderEIP1559) getDifficulty() uint64 {
	return h.Difficulty
}

func (h *HeaderEIP1559) getNumber() uint64 {
	return h.Number
}

func (h *HeaderEIP1559) getGasLimit() uint64 {
	return h.GasLimit
}

func (h *HeaderEIP1559) getGasUsed() uint64 {
	return h.GasUsed
}

func (h *HeaderEIP1559) getTimestamp() int64 {
	return h.Timestamp
}

func (h *HeaderEIP1559) getNonce() uint64 {
	return h.Nonce
}

func (h *HeaderEIP1559) getBaseFeePerGas() *big.Int {
	return h.BaseFeePerGas
}

func (h *HeaderEIP1559) getWithdrawalsRoot() Hash {
	return ZeroStorageHash // no withdrawals root
}

// SignaturePayload constructs the EIP-1559 header signature payload.
// The signature payload (what's being signed) is the keccak of a specific RLP encoding.
//
// RLP structure that needs to be constructed and keccak-ed later:
//
//   - RLP: [parentHash, unclesHash, coinbase, stateRoot, transactionsRoot,
//     receiptsRoot, logsBloom, difficulty, number, gasLimit, gasUsed, timestamp,
//     extraData, mixHash, nonce, baseFeePerGas]
func (h *HeaderEIP1559) SignaturePayload() []byte {
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
		ethrlp.EncodeBigInt(h.BaseFeePerGas),
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Keccak the RLP encoding
	return keccak.New().Hash(rlpEncoding)
}

// FromProto converts a protobuf Header to an EIP-1559 header
func (h *HeaderEIP1559) FromProto(pb *ethProto.Header) error {
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

	// Handle the payload
	payload, ok := pb.Payload.(*ethProto.Header_Eip1559)
	if !ok {
		return ErrInvalidHeaderPayload
	}

	h.BaseFeePerGas = big.NewInt(0).SetBytes(payload.Eip1559.BaseFeePerGas)

	return nil
}

// ToProto converts an EIP-1559 header proto to a protobuf Header
func (h *HeaderEIP1559) ToProto() *ethProto.Header {
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

	// Set EIP-1559 specific payload
	var baseFeeBytes []byte
	if h.BaseFeePerGas != nil {
		baseFeeBytes = h.BaseFeePerGas.Bytes()
	}

	pb.Payload = &ethProto.Header_Eip1559{
		Eip1559: &ethProto.EIP1559Payload{
			BaseFeePerGas: baseFeeBytes,
		},
	}

	return pb
}
