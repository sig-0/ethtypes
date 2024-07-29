package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// TestHash_Conversion verifies that random
// strings can be converted to the correct Hash format
func TestHash_Conversion(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		hash := StringToHash(
			rapid.String().Draw(t, "random value"),
		)

		assert.Len(t, hash, hashSize)
	})
}
