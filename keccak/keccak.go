package keccak

import (
	"golang.org/x/crypto/sha3"
)

type Keccak256 struct{}

// New creates a new Keccak256 hasher instance
func New() *Keccak256 {
	return &Keccak256{}
}

// Hash generates the keccak256 hash
// from the input bytes
func (k *Keccak256) Hash(data ...[]byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	for _, d := range data {
		hash.Write(d)
	}

	return hash.Sum(nil)
}
