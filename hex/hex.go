package hex

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"strings"
)

var ErrInvalidHexString = errors.New("invalid hex string")

const Prefix = "0x"

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
	return Prefix + strconv.FormatUint(num, 16)
}

// FromBigToHex returns the hexadecimal representation of the
// input big.Int (with the 0x prefix)
func FromBigToHex(num *big.Int) string {
	if num == nil {
		return Prefix
	}

	return Prefix + num.Text(16)
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

// DecodeHexToBig decodes the given hex big number to *big.Int.
// Returns nil if hex is "0x"
func DecodeHexToBig(hex string) (*big.Int, error) {
	// Check if the value is valid
	if hex == "" {
		return nil, ErrInvalidHexString
	}

	// Check if the value is "empty"
	if hex == Prefix {
		return nil, nil //nolint:nilnil // Mimics encode functionality
	}

	// Parse the hex
	result, success := big.NewInt(0).SetString(
		strings.TrimPrefix(hex, Prefix),
		16,
	)
	if !success {
		return nil, ErrInvalidHexString
	}

	return result, nil
}

// DecodeString is a wrapper for the standard hex.Decode string
// to avoid complicating imports
func DecodeString(str string) ([]byte, error) {
	return hex.DecodeString(str)
}
