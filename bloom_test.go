package ethtypes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBloom_BytesToBloom(t *testing.T) {
	t.Parallel()

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()

		b := BytesToBloom(nil)

		require.NotNil(t, b.Filter)
		assert.Zero(t, b.Filter.ApproximatedSize())
	})

	t.Run("valid input", func(t *testing.T) {
		t.Parallel()

		var (
			b   = NewBloom()
			set = []string{"test data 1", "test data 2"}
		)

		for _, item := range set {
			b.Filter.AddString(item)
		}

		// Serialize the bloom
		serialized := b.ToBytes()

		// Deserialize it
		deserialized := BytesToBloom(serialized)

		for _, item := range set {
			assert.True(t, deserialized.Filter.TestString(item))
		}
	})
}
