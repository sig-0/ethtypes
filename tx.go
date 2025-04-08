package ethtypes

import (
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/sig-0/ethcrypto/secp256k1"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

const (
	TransactionLegacy = 0x00
	Transaction2930   = 0x01
	Transaction1559   = 0x02
)

// transactionData is the wrapper for specific transaction types
// such as legacy, EIP-1559 and EIP-2930
type transactionData interface {
	// Common transaction types //

	// getType returns the transaction type
	getType() byte

	// getNonce returns the sender tx nonce
	getNonce() uint64

	// getGas returns the tx gas limit
	getGas() uint64

	// getTo returns the destination address (must be set)
	getTo() *Address

	// getValue returns the tx transfer value in wei
	getValue() *big.Int

	// getChainID returns the chain ID of the tx (if any)
	getChainID() *big.Int

	// getSigValues returns the tx signature values (if any)
	getSigValues() (v, r, s *big.Int)

	// getData returns the tx payload
	getData() []byte

	// getGasPrice returns the gas price of the tx (if any)
	getGasPrice() *big.Int

	// getHash returns the transaction hash (signature payload)
	getHash() Hash

	// EIP-1559 //

	// getMaxFeePerGas returns the maximum fee to be paid for unit of gas
	getMaxFeePerGas() *big.Int

	// getMaxPriorityFeePerGas returns the max priority fee per gas
	getMaxPriorityFeePerGas() *big.Int

	// EIP-2930 //

	// getAccessList returns the tx access list, if any
	getAccessList() AccessList
}

type Transaction struct {
	inner transactionData

	// Quick lookup
	from atomic.Value
	hash atomic.Value
}

// NewTransaction creates a new transaction wrapper
func NewTransaction(inner transactionData) *Transaction {
	return &Transaction{
		inner: inner,
	}
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
// If none is set (ex. contract deployment), it returns nil
func (t *Transaction) To() *Address {
	return t.inner.getTo()
}

// From returns the sender address (origin) of the transaction.
// The sender address is derived from the signature values
// of the transaction, if any are set.
//
// Assumes transaction signature values (V, R, S) are verified
func (t *Transaction) From() (*Address, error) {
	// Check if the sender was derived in the past
	if fromRaw := t.from.Load(); fromRaw != nil {
		from, _ := fromRaw.(Address)

		return &from, nil
	}

	var (
		txHash  = t.Hash()
		v, r, s = t.SigValues()
	)

	// Prepare the ECRecover payload
	payload := secp256k1.PrepareECRecover(txHash.ToBytes(), v, r, s)

	recoveredAddress, err := secp256k1.ECRecover(payload)
	if err != nil {
		return nil, fmt.Errorf("unable to ECRECOVER the address: %w", err)
	}

	// Save the derived address for future calls
	address := BytesToAddress(recoveredAddress)

	t.from.Store(address)

	return &address, nil
}

func (t *Transaction) Value() *big.Int {
	return t.inner.getValue()
}

func (t *Transaction) ChainID() *big.Int {
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

func (t *Transaction) AccessList() AccessList {
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

	// Calculate the transaction hash
	hash := t.inner.getHash()

	// Update the builtin transaction cache
	t.hash.Store(hash)

	return hash
}

// ToProto converts the Transaction into its proto representation
func (t *Transaction) ToProto() (*txProto.Transaction, error) {
	switch t.Type() {
	case TransactionLegacy:
		tx := t.inner.(*TxLegacy)

		return tx.ToProto(), nil
	case Transaction2930:
		tx := t.inner.(*TxEIP2930)

		return tx.ToProto(), nil
	case Transaction1559:
		tx := t.inner.(*TxEIP1559)

		return tx.ToProto(), nil
	}

	return nil, fmt.Errorf("unknown transaction type, %x", t.Type())
}

// FromProto converts a proto Transaction into a Transaction
func (t *Transaction) FromProto(pb *txProto.Transaction) error {
	if pb == nil {
		return ErrNilProtoTx
	}

	switch payload := pb.Payload.(type) {
	case *txProto.Transaction_Legacy:
		tx := &TxLegacy{}

		if err := tx.FromProto(pb); err != nil {
			return fmt.Errorf("unable to parse legacy proto: %w", err)
		}

		t.inner = tx
	case *txProto.Transaction_Eip2930:
		tx := &TxEIP2930{}

		if err := tx.FromProto(pb); err != nil {
			return fmt.Errorf("unable to parse EIP2930 proto: %w", err)
		}

		t.inner = tx
	case *txProto.Transaction_Eip1559:
		tx := &TxEIP1559{}

		if err := tx.FromProto(pb); err != nil {
			return fmt.Errorf("unable to parse EIP1559 proto: %w", err)
		}

		t.inner = tx
	default:
		return fmt.Errorf("unsupported proto payload type: %T", payload)
	}

	return nil
}
