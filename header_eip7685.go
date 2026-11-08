package ethtypes

import (
	"encoding/binary"
	"math/big"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/keccak"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var _ headerData = (*HeaderEIP7685)(nil)

// HeaderEIP7685 represents the EIP-7685 header,
// introduced as part of EIP-7685 (Prague hardfork)
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7685.md
type HeaderEIP7685 struct {
	BaseFeePerGas         *big.Int // Base fee per gas unit for EIP-1559 blocks
	ExtraData             []byte   // Extra data field, often used for creator-encoded information
	LogsBloom             Bloom    // Bloom filter for quick searching of logs in the block
	ParentHash            Hash     // Hash of the previous block (the parent block)
	UncleHash             Hash     // Hash of the uncles block list
	StateRoot             Hash     // Root of the state trie (Ethereum state at the end of this block)
	TransactionsRoot      Hash     // Root of the transactions trie (all transactions for this block)
	ReceiptsRoot          Hash     // Root of the receipts trie (all transaction receipts for this block)
	MixDigest             Hash     // Hash used in the proof-of-work algorithm (RANDAO value after the merge)
	WithdrawalsRoot       Hash     // Root of the withdrawals trie (for withdrawals from validators)
	ParentBeaconBlockRoot Hash     // Root of the parent beacon block
	RequestsHash          Hash     // Hash of the execution layer requests in the block
	Coinbase              Address  // Address of the block creator
	Difficulty            uint64   // The difficulty of mining the block (0 after the merge)
	Number                uint64   // The block number (height of the block in the chain)
	GasLimit              uint64   // Gas limit for the block
	GasUsed               uint64   // Total gas used by all transactions in the block
	Nonce                 uint64   // Random value used by the miner in proof-of-work (0 after the merge)
	BlobGasUsed           uint64   // Total blob gas used by all transactions in the block
	ExcessBlobGas         uint64   // Excess blob gas, used to calculate the blob base fee
	Timestamp             int64    // Timestamp when the block was created
}

func (h *HeaderEIP7685) getType() headerType {
	return headerEIP7685
}

func (h *HeaderEIP7685) getHash() Hash {
	return h.Hash()
}

func (h *HeaderEIP7685) getParentHash() Hash {
	return h.ParentHash
}

func (h *HeaderEIP7685) getUncleHash() Hash {
	return h.UncleHash
}

func (h *HeaderEIP7685) getStateRoot() Hash {
	return h.StateRoot
}

func (h *HeaderEIP7685) getTransactionsRoot() Hash {
	return h.TransactionsRoot
}

func (h *HeaderEIP7685) getReceiptsRoot() Hash {
	return h.ReceiptsRoot
}

func (h *HeaderEIP7685) getMixDigest() Hash {
	return h.MixDigest
}

func (h *HeaderEIP7685) getCoinbase() Address {
	return h.Coinbase
}

func (h *HeaderEIP7685) getLogsBloom() Bloom {
	return h.LogsBloom
}

func (h *HeaderEIP7685) getExtraData() []byte {
	return h.ExtraData
}

func (h *HeaderEIP7685) getDifficulty() uint64 {
	return h.Difficulty
}

func (h *HeaderEIP7685) getNumber() uint64 {
	return h.Number
}

func (h *HeaderEIP7685) getGasLimit() uint64 {
	return h.GasLimit
}

func (h *HeaderEIP7685) getGasUsed() uint64 {
	return h.GasUsed
}

func (h *HeaderEIP7685) getTimestamp() int64 {
	return h.Timestamp
}

func (h *HeaderEIP7685) getNonce() uint64 {
	return h.Nonce
}

func (h *HeaderEIP7685) getBaseFeePerGas() *big.Int {
	return h.BaseFeePerGas
}

func (h *HeaderEIP7685) getWithdrawalsRoot() Hash {
	return h.WithdrawalsRoot
}

func (h *HeaderEIP7685) getBlobGasUsed() uint64 {
	return h.BlobGasUsed
}

func (h *HeaderEIP7685) getExcessBlobGas() uint64 {
	return h.ExcessBlobGas
}

func (h *HeaderEIP7685) getParentBeaconBlockRoot() Hash {
	return h.ParentBeaconBlockRoot
}

func (h *HeaderEIP7685) getRequestsHash() Hash {
	return h.RequestsHash
}

// Hash constructs the EIP-7685 header hash.
// The hash is the keccak of the header's RLP encoding
func (h *HeaderEIP7685) Hash() Hash {
	// Perform the RLP encoding of the payload
	rlpEncoding := h.ToRLP()

	// Keccak the RLP encoding
	return BytesToHash(keccak.New().Hash(rlpEncoding))
}

// FromProto converts a protobuf Header to an EIP-7685 header
func (h *HeaderEIP7685) FromProto(pb *ethProto.Header) error {
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
	payload, ok := pb.Payload.(*ethProto.Header_Eip7685)
	if !ok {
		return ErrInvalidHeaderPayload
	}

	h.BaseFeePerGas = big.NewInt(0).SetBytes(payload.Eip7685.GetBaseFeePerGas())
	h.WithdrawalsRoot = BytesToHash(payload.Eip7685.GetWithdrawalsRoot())
	h.BlobGasUsed = payload.Eip7685.GetBlobGasUsed()
	h.ExcessBlobGas = payload.Eip7685.GetExcessBlobGas()
	h.ParentBeaconBlockRoot = BytesToHash(payload.Eip7685.GetParentBeaconBlockRoot())
	h.RequestsHash = BytesToHash(payload.Eip7685.GetRequestsHash())

	return nil
}

// ToProto converts an EIP-7685 header to a protobuf Header
func (h *HeaderEIP7685) ToProto() *ethProto.Header {
	pb := &ethProto.Header{
		Hash:             h.Hash().ToBytes(),
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

	// Set EIP-7685 specific payload
	pb.Payload = &ethProto.Header_Eip7685{
		Eip7685: &ethProto.EIP7685Payload{
			BaseFeePerGas:         bigToBytes(h.BaseFeePerGas),
			WithdrawalsRoot:       h.WithdrawalsRoot.ToBytes(),
			BlobGasUsed:           h.BlobGasUsed,
			ExcessBlobGas:         h.ExcessBlobGas,
			ParentBeaconBlockRoot: h.ParentBeaconBlockRoot.ToBytes(),
			RequestsHash:          h.RequestsHash.ToBytes(),
		},
	}

	return pb
}

// ToRLP encodes the EIP-7685 header using RLP encoding.
//
//   - RLP: [parentHash, unclesHash, coinbase, stateRoot, transactionsRoot,
//     receiptsRoot, logsBloom, difficulty, number, gasLimit, gasUsed, timestamp,
//     extraData, mixHash, nonce, baseFeePerGas, withdrawalsRoot, blobGasUsed,
//     excessBlobGas, parentBeaconBlockRoot, requestsHash]
func (h *HeaderEIP7685) ToRLP() []byte {
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
		ethrlp.EncodeBytes(binary.BigEndian.AppendUint64(nil, h.Nonce)), // the nonce is always 8 bytes
		ethrlp.EncodeBytes(bigToBytes(h.BaseFeePerGas)),
		ethrlp.EncodeBytes(h.WithdrawalsRoot.ToBytes()),
		ethrlp.EncodeUint(h.BlobGasUsed),
		ethrlp.EncodeUint(h.ExcessBlobGas),
		ethrlp.EncodeBytes(h.ParentBeaconBlockRoot.ToBytes()),
		ethrlp.EncodeBytes(h.RequestsHash.ToBytes()),
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	return rlpEncoding
}
