package ethtypes

import (
	"errors"
	"math/big"

	"github.com/sig-0/ethtypes/keccak"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var ErrNilProtoAcc = errors.New("proto account is nil")

var (
	// ZeroStorageHash is the historical Ethereum MPT value (empty trie root)
	ZeroStorageHash = StringToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	ZeroCodeHash    = BytesToHash(keccak.New().Hash([]byte{}))
)

// Account is a single Ethereum account representation
type Account struct {
	Balance     *big.Int // balance in wei
	Nonce       uint64   // account sequence
	StorageRoot Hash     // hash of the root node of the account storage trie. Empty account storage is ZeroStorageHash
	CodeHash    Hash     // hash of the EVM code of this account. For EOAs, this is the hash of an empty string
}

// IsEOA returns a flag indicating if an account is an EOA (Externally Owned Account).
// Conditions for an account being an EOA:
//
// 1. The storage root is empty (zero hash)
//
// 2. The code hash is the keccak hash of an empty string
func (a *Account) IsEOA() bool {
	return a.StorageRoot == ZeroStorageHash && a.CodeHash == ZeroCodeHash
}

// FromProto loads the account data from the given proto representation
func (a *Account) FromProto(protoAccount *ethProto.Account) error {
	if protoAccount == nil {
		return ErrNilProtoAcc
	}

	a.Nonce = protoAccount.Nonce
	a.Balance = big.NewInt(0).SetBytes(protoAccount.Balance)
	a.StorageRoot = BytesToHash(protoAccount.StorageRoot)
	a.CodeHash = BytesToHash(protoAccount.CodeHash)

	return nil
}

// ToProto generates a proto representation of an account
func (a *Account) ToProto() *ethProto.Account {
	return &ethProto.Account{
		Nonce:       a.Nonce,
		Balance:     a.Balance.Bytes(),
		StorageRoot: a.StorageRoot.ToBytes(),
		CodeHash:    a.CodeHash.ToBytes(),
	}
}
