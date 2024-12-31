package ethtypes

import (
	"math/big"

	"github.com/sig-0/ethtypes/keccak"
)

var ZeroCodeHash = BytesToHash(keccak.New().Hash([]byte{}))

type Account struct {
	Balance     *big.Int // balance in wei
	Nonce       uint64   // account sequence
	StorageRoot Hash     // hash of the root node of the account storage trie
	CodeHash    Hash     // hash of the EVM code of this account. For EOAs, this is the hash of an empty string
}

// IsEOA returns a flag indicating if an account is an EOA (Externally Owned Account).
// Conditions for an account being an EOA:
//
// 1. The storage root is empty (zero hash)
//
// 2. The code hash is the keccak hash of an empty string
func (a Account) IsEOA() bool {
	return a.StorageRoot == ZeroHash && a.CodeHash == ZeroCodeHash
}
