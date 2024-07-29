package types

import "github.com/sig-0/ethtypes/hex"

const (
	hashSize = 32 // Bytes
)

// ZeroHash represents a placeholder
// hash value that contains all zero bytes
//
//nolint:gochecknoglobals // Common global value
var ZeroHash = Hash{}

type Hash [hashSize]byte

// ToString converts the specific hash
// to a string hex representation
func (h Hash) ToString() string {
	return hex.ToHexString(h[:])
}

// ToBytes converts the specific hash to
// a bytes representation
func (h Hash) ToBytes() []byte {
	return h[:]
}

// BytesToHash converts the specified hash
// bytes into a Hash representation (32B)
func BytesToHash(hash []byte) Hash {
	var (
		h Hash

		size    = len(hash)
		minSize = min(size, hashSize)
	)

	copy(
		h[hashSize-minSize:],
		hash[size-minSize:],
	)

	return h
}

// StringToHash converts the specified hash
// string into a Hash representation
func StringToHash(input string) Hash {
	return BytesToHash(stringToHexBytes(input))
}
