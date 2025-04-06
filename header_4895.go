package ethtypes

import (
	"math/big"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/keccak"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var _ headerData = (*HeaderEIP4895)(nil)

// HeaderEIP4895 represents the EIP-4895 header,
// introduced as part of EIP-4895 (Shanghai hardfork)
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4895.md
type HeaderEIP4895 struct {
	LogsBloom        *Bloom   // Bloom filter for quick searching of logs in the block
	BaseFeePerGas    *big.Int // Base fee per gas unit for EIP-1559 blocks
	ExtraData        []byte   // Extra data field, often used for creator-encoded information
	ParentHash       Hash     // Hash of the previous block (the parent block)
	UncleHash        Hash     // Hash of the uncles block list
	StateRoot        Hash     // Root of the state trie (Ethereum state at the end of this block)
	TransactionsRoot Hash     // Root of the transactions trie (all transactions for this block)
	ReceiptsRoot     Hash     // Root of the receipts trie (all transaction receipts for this block)
	MixDigest        Hash     // Hash used in the proof-of-work algorithm (before Ethereum 2.0)
	WithdrawalsRoot  Hash     // Root of the withdrawals trie (for withdrawals from validators)
	Coinbase         Address  // Address of the block creator
	Difficulty       uint64   // The difficulty of mining the block
	Number           uint64   // The block number (height of the block in the chain)
	GasLimit         uint64   // Gas limit for the block
	GasUsed          uint64   // Total gas used by all transactions in the block
	Nonce            uint64   // Random value used by the miner in proof-of-work (before Ethereum 2.0)
	Timestamp        int64    // Timestamp when the block was created
}

func (h *HeaderEIP4895) getHash() Hash {
	return BytesToHash(h.SignaturePayload())
}

func (h *HeaderEIP4895) getParentHash() Hash {
	return h.ParentHash
}

func (h *HeaderEIP4895) getUncleHash() Hash {
	return h.UncleHash
}

func (h *HeaderEIP4895) getStateRoot() Hash {
	return h.StateRoot
}

func (h *HeaderEIP4895) getTransactionsRoot() Hash {
	return h.TransactionsRoot
}

func (h *HeaderEIP4895) getReceiptsRoot() Hash {
	return h.ReceiptsRoot
}

func (h *HeaderEIP4895) getMixDigest() Hash {
	return h.MixDigest
}

func (h *HeaderEIP4895) getCoinbase() Address {
	return h.Coinbase
}

func (h *HeaderEIP4895) getLogsBloom() *Bloom {
	return h.LogsBloom
}

func (h *HeaderEIP4895) getExtraData() []byte {
	return h.ExtraData
}

func (h *HeaderEIP4895) getDifficulty() uint64 {
	return h.Difficulty
}

func (h *HeaderEIP4895) getNumber() uint64 {
	return h.Number
}

func (h *HeaderEIP4895) getGasLimit() uint64 {
	return h.GasLimit
}

func (h *HeaderEIP4895) getGasUsed() uint64 {
	return h.GasUsed
}

func (h *HeaderEIP4895) getTimestamp() int64 {
	return h.Timestamp
}

func (h *HeaderEIP4895) getNonce() uint64 {
	return h.Nonce
}

func (h *HeaderEIP4895) getBaseFeePerGas() *big.Int {
	return h.BaseFeePerGas
}

func (h *HeaderEIP4895) getWithdrawalsRoot() Hash {
	return h.WithdrawalsRoot
}

// SignaturePayload constructs the EIP-4895 header signature payload.
// The signature payload (what's being signed) is the keccak of a specific RLP encoding.
//
// RLP structure that needs to be constructed and keccak-ed later:
//
//   - RLP: [parentHash, unclesHash, coinbase, stateRoot, transactionsRoot,
//     receiptsRoot, logsBloom, difficulty, number, gasLimit, gasUsed, timestamp,
//     extraData, mixHash, nonce, baseFeePerGas, withdrawalsRoot]
func (h *HeaderEIP4895) SignaturePayload() []byte {
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
		ethrlp.EncodeBytes(h.WithdrawalsRoot.ToBytes()),
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Keccak the RLP encoding
	return keccak.New().Hash(rlpEncoding)
}

// FromProto converts a protobuf Header to an EIP-4895 header
func (h *HeaderEIP4895) FromProto(pb *ethProto.Header) error {
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
	payload, ok := pb.Payload.(*ethProto.Header_Eip4895)
	if !ok {
		return ErrInvalidHeaderPayload
	}

	h.BaseFeePerGas = big.NewInt(0).SetBytes(payload.Eip4895.BaseFeePerGas)
	h.WithdrawalsRoot = BytesToHash(payload.Eip4895.WithdrawalsRoot)

	return nil
}

// ToProto converts an EIP-4895 header proto to a protobuf Header
func (h *HeaderEIP4895) ToProto() *ethProto.Header {
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

	// Set EIP-4895 specific payload
	var baseFeeBytes []byte
	if h.BaseFeePerGas != nil {
		baseFeeBytes = h.BaseFeePerGas.Bytes()
	}

	pb.Payload = &ethProto.Header_Eip4895{
		Eip4895: &ethProto.EIP4895Payload{
			BaseFeePerGas:   baseFeeBytes,
			WithdrawalsRoot: h.WithdrawalsRoot.ToBytes(),
		},
	}

	return pb
}
