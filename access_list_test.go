package ethtypes

import (
	"bytes"
	"testing"

	"github.com/sig-0/ethrlp"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EIP-2930, section "Specification", the access list example
func TestAccessListEIP2930Example(t *testing.T) {
	t.Parallel()

	list := AccessList{
		{
			Address: StringToAddress("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"),
			StorageKeys: []Hash{
				StringToHash("0x0000000000000000000000000000000000000000000000000000000000000003"),
				StringToHash("0x0000000000000000000000000000000000000000000000000000000000000007"),
			},
		},
		{
			Address: StringToAddress("0xbb9bc244d798123fde783fcc1c72d3bb8c189413"),
		},
	}

	var fromRLP AccessList

	require.NoError(t, fromRLP.FromRLP(list.ToRLP()))
	require.Len(t, fromRLP, 2)
	assert.Equal(t, list[0].Address, fromRLP[0].Address)
	assert.Equal(t, list[0].StorageKeys, fromRLP[0].StorageKeys)
	assert.Equal(t, list[1].Address, fromRLP[1].Address)
	assert.Empty(t, fromRLP[1].StorageKeys)

	var entry AccessListEntry

	require.NoError(t, entry.FromRLP(list[0].ToRLP()))
	assert.Equal(t, list[0].ToRLP(), entry.ToRLP())

	var fromProto AccessList

	fromProto.FromProto(list.ToProto())
	assert.Equal(t, list.ToRLP(), fromProto.ToRLP())
}

// Real mainnet access lists, which the old decoder rejected
func TestAccessListMainnetRegression(t *testing.T) {
	t.Parallel()

	testTable := []struct {
		decode func(payload []byte) (AccessList, error)
		name   string
		raw    string
		want   AccessList
	}{
		{
			// Mainnet block 13500264, tx 0x36a2c13b12683d9d1b013fd85d04d84272d5ababba05ca508c71fbe61ea0fd5b
			name: "type 1, entry without storage keys",
			raw:  "0x01f901d201825dcb8523c3b8f7df8305a32394000000000000f0bc41c73af48f022f8c27b5350e80b90150002c000000d8d40abf7e456f20e95253e54490d8d30ea41574b24f741ee70201000000000000000000000124022c0d9f000000000000000000000000000000000000000000000000000000163d6c4d470000000000000000000000000000000000000000000000000000000000000000000000000000000000000000230000377650db9ca400d3fdff490000768521000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000007c88e6a0c2ddd26feeb64f039a2c41296fcb3f5640a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000014a5ed3e603a9eb2b00000000000000000000000000000000000000000000000001dfa18888ef5f7000000000d7d69420e95253e54490d8d30ea41574b24f741ee70201c080a09148491202dc360e30d294d4d7f058771167ad2076523581de33a1b3c2c65489a028a3f7ac01467999a59d2c61008e73623d85e8c6dd680efd2e0f511238a89adf",
			decode: func(payload []byte) (AccessList, error) {
				var tx TxEIP2930

				err := tx.FromRLP(payload)

				return tx.AccessList, err
			},
			want: AccessList{
				{Address: StringToAddress("0x20e95253e54490d8d30ea41574b24f741ee70201")},
			},
		},
		{
			// Mainnet block 16000036, tx 0x5cc0107499d668aab889c01a9c02b11964625c0aebb567e4d9e3bbb66b937146
			name: "type 2, entry with one storage key",
			raw:  "0x02f8af01826c72849502f9008505fa03367e82b98c94007933790a4f00000099e9001629d9fe7775b8008502b2801ebf845207a120f838f794c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2e1a05b1fd252f972f66f1de33cbc3b44509a4ec1fc4dee11857461b8b9131f605c4201a05289194989291140fced942d94199bcb92a3091ad22af124d67b498c0f47c35aa03255bccb0e7325f3996fbe7996e5a86a643086f22f0f4fc2e43a01880370d39c",
			decode: func(payload []byte) (AccessList, error) {
				var tx TxEIP1559

				err := tx.FromRLP(payload)

				return tx.AccessList, err
			},
			want: AccessList{
				{
					Address:     StringToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
					StorageKeys: []Hash{StringToHash("0x5b1fd252f972f66f1de33cbc3b44509a4ec1fc4dee11857461b8b9131f605c42")},
				},
			},
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			list, err := testCase.decode(hexBytes(t, testCase.raw)[1:])
			require.NoError(t, err)
			assert.Equal(t, testCase.want.ToRLP(), list.ToRLP())
		})
	}
}

func TestAccessListFromRLPRejects(t *testing.T) {
	t.Parallel()

	entry := func(items ...[]byte) []byte {
		return ethrlp.EncodeArray([][]byte{ethrlp.EncodeArray(items)})
	}

	noKeys := ethrlp.EncodeArray(nil)

	testTable := []struct {
		name  string
		input []byte
	}{
		{name: "19-byte address", input: entry(ethrlp.EncodeBytes(make([]byte, 19)), noKeys)},
		{name: "21-byte address", input: entry(ethrlp.EncodeBytes(make([]byte, 21)), noKeys)},
		{
			name: "33-byte storage key",
			input: entry(
				ethrlp.EncodeBytes(make([]byte, 20)),
				ethrlp.EncodeArray([][]byte{ethrlp.EncodeBytes(bytes.Repeat([]byte{0x01}, 33))}),
			),
		},
		{name: "3-item entry", input: entry(ethrlp.EncodeBytes(make([]byte, 20)), noKeys, noKeys)},
		{name: "nil input", input: nil},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var list AccessList

			assert.ErrorIs(t, list.FromRLP(testCase.input), ErrInvalidRLPAccessList)
		})
	}

	t.Run("FromRLPValues replaces", func(t *testing.T) {
		t.Parallel()

		decoded, err := ethrlp.DecodeBytes(entry(ethrlp.EncodeBytes(make([]byte, 20)), noKeys))
		require.NoError(t, err)

		values, ok := decoded.GetValue().([]ethrlp.Value)
		require.True(t, ok)

		var list AccessList

		require.NoError(t, list.FromRLPValues(values))
		require.NoError(t, list.FromRLPValues(values))
		assert.Len(t, list, 1)
	})

	t.Run("AccessListEntry.FromRLP with a 19-byte address", func(t *testing.T) {
		t.Parallel()

		valid := ethrlp.EncodeArray([][]byte{ethrlp.EncodeBytes(make([]byte, 20)), noKeys})
		bad := ethrlp.EncodeArray([][]byte{ethrlp.EncodeBytes(make([]byte, 19)), noKeys})

		assertDecodeRejects[AccessListEntry](t, valid, bad)
		assert.ErrorIs(t, (&AccessListEntry{}).FromRLP(bad), ErrInvalidRLPAccessList)
	})
}

func TestAccessListFromProtoNilEntry(t *testing.T) {
	t.Parallel()

	var list AccessList

	list.FromProto([]*txProto.AccessListEntry{nil})
	require.Len(t, list, 1)
	assert.Equal(t, Address{}, list[0].Address)
	assert.Empty(t, list[0].StorageKeys)

	entry := AccessListEntry{
		Address:     StringToAddress("0x0000000000000000000000000000000000000001"),
		StorageKeys: []Hash{{0x01}},
	}

	entry.FromProto(nil)
	assert.Equal(t, Address{}, entry.Address)
	assert.Empty(t, entry.StorageKeys)
}
