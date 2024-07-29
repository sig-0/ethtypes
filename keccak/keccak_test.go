package keccak

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// TestKeccak_Hash verifies the output
// format for the Keccak256 wrapper
func TestKeccak_Hash(t *testing.T) {
	t.Parallel()

	const hashSize = 32 // Bytes

	// There is no sense in verifying
	// the standard sha3 library, instead
	// the format of the defined wrapper is checked
	rapid.Check(t, func(t *rapid.T) {
		hasher := New()
		hash := hasher.Hash(
			[]byte(
				rapid.String().Draw(t, "random string value"),
			),
		)

		assert.Len(t, hash, hashSize)
	})
}
