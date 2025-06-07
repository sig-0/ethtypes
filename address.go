package ethtypes

import (
	"bytes"
	"strings"
	"unicode"

	"github.com/sig-0/ethtypes/hex"
	"github.com/sig-0/ethtypes/keccak"
)

const (
	addressSize = 20 // Bytes
)

// ZeroAddress represents a placeholder
// address value that contains all zero bytes
//
//nolint:gochecknoglobals // Common global value
var ZeroAddress = Address{}

type Address [addressSize]byte

// ToString converts the specific address
// to a string representation (checksummed)
func (a Address) ToString() string {
	return a.checksumAddress()
}

// ToBytes converts the specific address to
// a bytes representation
func (a Address) ToBytes() []byte {
	return a[:]
}

// Equals checks if two addresses are equal
func (a Address) Equals(b Address) bool {
	return bytes.Equal(a[:], b[:])
}

// stringToHexBytes converts the input string
// to a hex representation, by:
// - trimming the prefix, if any
// - padding to even length
// - decoding from hex
func stringToHexBytes(input string) []byte {
	// Make sure the input string does not
	// contain the 0x prefix
	raw := strings.TrimPrefix(input, hex.Prefix)

	// Make sure the length of the raw
	// string is even
	if len(raw)%2 == 1 {
		raw = "0" + raw
	}

	// Convert the input string to a valid
	// hex byte representation
	//nolint:errcheck // Should never error out
	h, _ := hex.DecodeString(raw)

	return h
}

// StringToAddress converts the specified address
// string into an Address representation
func StringToAddress(input string) Address {
	return BytesToAddress(stringToHexBytes(input))
}

// BytesToAddress converts the specified address
// bytes into an Address representation (20B)
func BytesToAddress(address []byte) Address {
	var (
		a Address

		size    = len(address)
		minSize = min(size, addressSize)
	)

	copy(
		a[addressSize-minSize:],
		address[size-minSize:],
	)

	return a
}

// checksumAddress returns the checksummed address
// representation, as outlined in
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
func (a Address) checksumAddress() string {
	lowercaseHex := hex.ToHexString(a.ToBytes())[2:]
	hashedAddress := hex.ToHexString(keccak.New().Hash([]byte(lowercaseHex)))[2:]

	result := make([]rune, len(lowercaseHex))

	for idx, ch := range lowercaseHex {
		if hashedAddress[idx] < '8' {
			result[idx] = ch
		} else {
			result[idx] = unicode.ToUpper(ch)
		}
	}

	return hex.Prefix + string(result)
}
