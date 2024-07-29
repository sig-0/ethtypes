package ethtypes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

// TestEIP55 verifies the Address string
// representation is checksummed, as per EIP-55
func TestEIP55(t *testing.T) {
	t.Parallel()

	testTable := []struct {
		name     string
		expected string
		address  Address
	}{
		// Test cases taken from EIP-55
		{
			"EIP-55 #1",
			"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
			StringToAddress("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
		},
		{
			"EIP-55 #2",
			"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
			StringToAddress("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"),
		},
		{
			"EIP-55 #3",
			"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
			StringToAddress("0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb"),
		},
		{
			"EIP-55 #4",
			"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
			StringToAddress("0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb"),
		},
	}

	for _, testCase := range testTable {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(
				t,
				testCase.expected,
				testCase.address.ToString(),
			)
		})
	}
}

// TestAddress_Conversion verifies that random
// strings can be converted to the correct Address format
func TestAddress_Conversion(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		hash := StringToAddress(
			rapid.String().Draw(t, "random value"),
		)

		assert.Len(t, hash, addressSize)
	})
}
