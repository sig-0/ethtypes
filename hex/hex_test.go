package hex

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestHex_FromHexString(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		original := []byte(
			rapid.String().Draw(t, "random value"),
		)

		decoded, err := FromHexString(ToHexString(original))
		require.NoError(t, err)

		assert.True(t, bytes.Equal(original, decoded))
	})
}

func TestHex_FromUintToHex(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		original := rapid.Uint64().Draw(t, "random value")

		decoded, err := DecodeHexToUint(FromUintToHex(original))
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})
}

func TestHex_FromBigToHex(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		var (
			drawn    = rapid.Uint64().Draw(t, "random value")
			original = big.NewInt(0).SetUint64(drawn)
		)

		decoded, err := DecodeHexToBig(FromBigToHex(original))
		require.NoError(t, err)

		assert.Equal(t, original.Bytes(), decoded.Bytes())
	})
}
