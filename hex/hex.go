package hex

import (
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"
)

const (
	Prefix = "0x"
)

// ToHexString converts the input data
// to a hex string representation with the 0x prefix
func ToHexString(input []byte) string {
	return Prefix + hex.EncodeToString(input)
}

// FromHexString converts an input string (with or without 0x)
// into a byte representation
func FromHexString(input string) ([]byte, error) {
	return hex.DecodeString(
		strings.TrimPrefix(input, Prefix),
	)
}

// FromUintToHex returns the hexadecimal representation of the
// input uint (with the 0x prefix)
func FromUintToHex(num uint64) string {
	return "0x" + strconv.FormatUint(num, 16)
}

// FromByteToHex returns the hexadecimal representation of
// the input byte
func FromByteToHex(value byte) string {
	return FromUintToHex(uint64(value))
}

// FromBigToHex returns the hexadecimal representation of the
// input big.Int (with the 0x prefix)
func FromBigToHex(num *big.Int) string {
	if num == nil {
		return "0x"
	}

	return "0x" + num.Text(16)
}

// DecodeHexToUint decodes the given hex number to a unit
func DecodeHexToUint(hex string) (uint64, error) {
	result, err := strconv.ParseUint(
		strings.TrimPrefix(hex, Prefix),
		16,
		64,
	)

	return result, err
}

// DecodeString is a wrapper for the standard hex.Decode string
// to avoid complicating imports
func DecodeString(str string) ([]byte, error) {
	return hex.DecodeString(str)
}
