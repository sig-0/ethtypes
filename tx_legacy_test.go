package ethtypes

import (
	"math/big"
	"strings"
	"testing"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/hex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeLegacyTxHash(t *testing.T) {
	t.Parallel()

	decodeHex := func(h string) []byte {
		r := strings.NewReplacer("\t", "", " ", "", "\n", "")

		decoded, err := hex.FromHexString(r.Replace(h))
		require.NoError(t, err)

		return decoded
	}

	initBig := func(value string) *big.Int {
		val, ok := big.NewInt(0).SetString(value, 10)
		require.True(t, ok)

		return val
	}

	testTable := []struct {
		name         string
		gasPrice     *big.Int
		value        *big.Int
		v            *big.Int
		r            *big.Int
		s            *big.Int
		to           []byte
		data         []byte
		expectedHash []byte
		nonce        uint64
		gasLimit     uint64
	}{
		{
			"EIP-155 example",
			big.NewInt(0).Mul(big.NewInt(20), big.NewInt(1000000000)),
			big.NewInt(0).Exp(big.NewInt(10), big.NewInt(18), nil),
			initBig("37"),
			initBig("18515461264373351373200002665853028612451056578545711640558177340181847433846"),
			initBig("46948507304638947509940763649030358759909902576025900602547168820602576006531"),
			decodeHex("3535353535353535353535353535353535353535"),
			[]byte{},
			decodeHex("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"),
			9,
			21000,
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// Encode the transaction
			rlpEncoding := ethrlp.EncodeArray([][]byte{
				ethrlp.EncodeUint(testCase.nonce),
				ethrlp.EncodeBigInt(testCase.gasPrice),
				ethrlp.EncodeUint(testCase.gasLimit),
				ethrlp.EncodeBytes(testCase.to),
				ethrlp.EncodeBigInt(testCase.value),
				ethrlp.EncodeBytes(testCase.data),
				ethrlp.EncodeBigInt(testCase.v),
				ethrlp.EncodeBigInt(testCase.r),
				ethrlp.EncodeBigInt(testCase.s),
			})

			tx := &TxLegacy{}

			require.NoError(t, tx.FromRLP(rlpEncoding))

			// Compute the signature payload, and make sure it's valid
			assert.Equal(t, testCase.expectedHash, tx.SignaturePayload())
		})
	}
}
