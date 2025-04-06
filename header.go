package ethtypes

import (
	"math/big"
	"sync/atomic"
)

// Header is the
type Header struct {
	inner headerData

	// Quick lookup
	hash atomic.Value
}

// headerData is the wrapper for specific transaction types
// such as legacy, EIP-1559 and EIP-4895
type headerData interface {
	// Common header types //

	getHash() Hash
	getParentHash() Hash
	getUncleHash() Hash
	getStateRoot() Hash
	getTransactionsRoot() Hash
	getReceiptsRoot() Hash
	getMixDigest() Hash
	getCoinbase() Address
	getLogsBloom() Bloom
	getExtraData() []byte
	getDifficulty() uint64
	getNumber() uint64
	getGasLimit() uint64
	getGasUsed() uint64
	getTimestamp() int64
	getNonce() uint64

	// EIP-1559 + EIP-4895 //
	getBaseFeePerGas() *big.Int

	// EIP-4895 //
	getWithdrawalsRoot() Hash
}

// NewHeader creates a new header wrapper
func NewHeader(inner headerData) *Header {
	return &Header{
		inner: inner,
	}
}

func (h *Header) Hash() Hash {
	// Load the hash from the built-in type cache
	// for quick lookup, if it's present
	if hashRaw := h.hash.Load(); hashRaw != nil {
		hash, _ := hashRaw.(Hash)

		return hash
	}

	// Calculate the header (block) hash
	hash := h.inner.getHash()

	// Update the builtin header (block) cache
	h.hash.Store(hash)

	return hash
}

func (h *Header) ParentHash() Hash {
	return h.inner.getParentHash()
}

func (h *Header) UncleHash() Hash {
	return h.inner.getUncleHash()
}

func (h *Header) StateRoot() Hash {
	return h.inner.getStateRoot()
}

func (h *Header) TransactionsRoot() Hash {
	return h.inner.getTransactionsRoot()
}

func (h *Header) ReceiptsRoot() Hash {
	return h.inner.getReceiptsRoot()
}

func (h *Header) MixDigest() Hash {
	return h.inner.getMixDigest()
}

func (h *Header) Beneficiary() Address {
	return h.inner.getCoinbase()
}

func (h *Header) LogsBloom() Bloom {
	return h.inner.getLogsBloom()
}

func (h *Header) ExtraData() []byte {
	return h.inner.getExtraData()
}

func (h *Header) Difficulty() uint64 {
	return h.inner.getDifficulty()
}

func (h *Header) Number() uint64 {
	return h.inner.getNumber()
}

func (h *Header) GasLimit() uint64 {
	return h.inner.getGasLimit()
}

func (h *Header) GasUsed() uint64 {
	return h.inner.getGasUsed()
}

func (h *Header) Timestamp() int64 {
	return h.inner.getTimestamp()
}

func (h *Header) Nonce() uint64 {
	return h.inner.getNonce()
}

func (h *Header) BaseFeePerGas() *big.Int {
	return h.inner.getBaseFeePerGas()
}

func (h *Header) WithdrawalsRoot() Hash {
	return h.inner.getWithdrawalsRoot()
}
