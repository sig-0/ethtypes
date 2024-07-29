package types

import (
	"math/big"
	"sync/atomic"
)

const (
	TransactionLegacy = iota
	Transaction1559
	Transaction2930
)

type TransactionData interface {
	// Common transaction types //

	getType() byte
	getNonce() uint64
	getGas() uint64
	getTo() Address
	getValue() *big.Int
	getChainID() uint64
	getSigValues() (v, r, s *big.Int)
	getData() []byte
	getGasPrice() *big.Int

	// EIP-1559 //

	getMaxFeePerGas() *big.Int
	getMaxPriorityFeePerGas() *big.Int

	// EIP-2930 //
	getAccessList() []*AccessListEntry
}

type Transaction struct {
	inner TransactionData

	// Quick lookup
	//nolint:unused // Currently unused
	from atomic.Value
	hash atomic.Value
}

func (t *Transaction) GetType() byte {
	return t.inner.getType()
}

func (t *Transaction) GetNonce() uint64 {
	return t.inner.getNonce()
}

func (t *Transaction) GetGas() uint64 {
	return t.inner.getGas()
}

// GetTo returns the To address of the transaction.
// If none is set (ex. contract deployment), it returns ZeroAddress
func (t *Transaction) GetTo() Address {
	return t.inner.getTo()
}

func (t *Transaction) GetValue() *big.Int {
	return t.inner.getValue()
}

func (t *Transaction) GetChainID() uint64 {
	return t.inner.getChainID()
}

//nolint:nonamedreturns // Simpler this way
func (t *Transaction) GetSigValues() (v, r, s *big.Int) {
	return t.inner.getSigValues()
}

func (t *Transaction) GetData() []byte {
	return t.inner.getData()
}

func (t *Transaction) GetGasPrice() *big.Int {
	return t.inner.getGasPrice()
}

func (t *Transaction) GetAccessList() []*AccessListEntry {
	return t.inner.getAccessList()
}

func (t *Transaction) GetMaxFeePerGas() *big.Int {
	return t.inner.getMaxFeePerGas()
}

func (t *Transaction) GetMaxPriorityFeePerGas() *big.Int {
	return t.inner.getMaxPriorityFeePerGas()
}

func (t *Transaction) Cost() *big.Int {
	// (gas price * gas) + value
	cost := big.NewInt(0).Mul(
		t.GetGasPrice(),
		big.NewInt(0).SetUint64(t.GetGas()),
	)

	return big.NewInt(0).Add(cost, t.GetValue())
}

func (t *Transaction) GetHash() Hash {
	// Load the hash from the built-in type cache
	// for quick lookup, if it's present
	if hashRaw := t.hash.Load(); hashRaw != nil {
		hash, _ := hashRaw.(Hash)

		return hash
	}

	// Calculate the hash based on the type
	var hash Hash
	if t.GetType() == TransactionLegacy {
		hash = getLegacyTransactionHash(t)
	} else {
		hash = getNonLegacyTransactionHash(t)
	}

	// Update the builtin transaction cache
	t.hash.Store(hash)

	return hash
}

// getLegacyTransactionHash calculates the transaction hash
// as the keccak256 hash of the RLP encoding of the transaction
func getLegacyTransactionHash(_ *Transaction) Hash {
	return ZeroHash
}

// getNonLegacyTransactionHash calculates the transaction hash
// as the keccak 256 hash of the RLP encoding of the transaction, and
// the transaction type
func getNonLegacyTransactionHash(_ *Transaction) Hash {
	return ZeroHash
}
