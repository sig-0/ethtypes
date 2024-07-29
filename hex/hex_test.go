package hex

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// TestHex_ToHexString verifies that the input
// can be converted to a hex string
func TestHex_ToHexString(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		str := ToHexString(
			[]byte(
				rapid.String().Draw(t, "random value"),
			),
		)

		assert.Contains(t, str, Prefix)
	})
}

// TestHex_ToHexString verifies that the input hex
// can be converted to a byte representation
func TestHex_FromHexString(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		original := []byte(
			rapid.String().Draw(t, "random value"),
		)

		decoded, err := FromHexString(ToHexString(original))
		if err != nil {
			t.Fatalf("unable to decode hex value, %v", err)
		}

		assert.True(t, bytes.Equal(original, decoded))
	})
}
