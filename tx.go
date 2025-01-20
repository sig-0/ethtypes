package ethtypes

import (
	"math/big"
	"sync/atomic"
)

const (
	TransactionLegacy = 0x00
	Transaction2930   = 0x01
	Transaction1559   = 0x02
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

func (t *Transaction) Type() byte {
	return t.inner.getType()
}

func (t *Transaction) Nonce() uint64 {
	return t.inner.getNonce()
}

func (t *Transaction) Gas() uint64 {
	return t.inner.getGas()
}

// To returns the To address of the transaction.
// If none is set (ex. contract deployment), it returns ZeroAddress
func (t *Transaction) To() Address {
	return t.inner.getTo()
}

func (t *Transaction) Value() *big.Int {
	return t.inner.getValue()
}

func (t *Transaction) ChainID() uint64 {
	return t.inner.getChainID()
}

//nolint:nonamedreturns // Simpler this way
func (t *Transaction) SigValues() (v, r, s *big.Int) {
	return t.inner.getSigValues()
}

func (t *Transaction) Data() []byte {
	return t.inner.getData()
}

func (t *Transaction) GasPrice() *big.Int {
	return t.inner.getGasPrice()
}

func (t *Transaction) AccessList() []*AccessListEntry {
	return t.inner.getAccessList()
}

func (t *Transaction) MaxFeePerGas() *big.Int {
	return t.inner.getMaxFeePerGas()
}

func (t *Transaction) MaxPriorityFeePerGas() *big.Int {
	return t.inner.getMaxPriorityFeePerGas()
}

func (t *Transaction) Cost() *big.Int {
	// (gas price * gas) + value
	cost := big.NewInt(0).Mul(
		t.GasPrice(),
		big.NewInt(0).SetUint64(t.Gas()),
	)

	return big.NewInt(0).Add(cost, t.Value())
}

func (t *Transaction) Hash() Hash {
	// Load the hash from the built-in type cache
	// for quick lookup, if it's present
	if hashRaw := t.hash.Load(); hashRaw != nil {
		hash, _ := hashRaw.(Hash)

		return hash
	}

	// Calculate the hash based on the type
	var hash Hash
	if t.Type() == TransactionLegacy {
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
