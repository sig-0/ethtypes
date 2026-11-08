package ethtypes

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/sig-0/ethrlp"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationListRLP(t *testing.T) {
	t.Parallel()

	testTable := []struct {
		name           string
		raw            string
		authorizations AuthorizationList
	}{
		{
			// Mainnet block 26364325 (Osaka), tx 0x7a5a82345b57a178c566008b0bd49fb240a31b9d253f7a4fe145861aab4d2054,
			// the authorization list of the transaction
			name: "mainnet authorization",
			raw:  "0xf85ff85d019484d05511614272694d3a9cebe896514dbde51f40830a2b4c01a0e4c73108b381a4ff6f94b90792466649e53278da479391958d055514e3f1b452a01fd74be7e6ed80c819c5942a245d2e09fc8a943fc718fe901915174569d05256",
			authorizations: AuthorizationList{
				{
					ChainID: big.NewInt(1),
					YParity: big.NewInt(1),
					R:       bigHex(t, "0xe4c73108b381a4ff6f94b90792466649e53278da479391958d055514e3f1b452"),
					S:       bigHex(t, "0x1fd74be7e6ed80c819c5942a245d2e09fc8a943fc718fe901915174569d05256"),
					Address: StringToAddress("0x84d05511614272694d3a9cebe896514dbde51f40"),
					Nonce:   0xa2b4c,
				},
			},
		},
		{
			// rlp([rlp([0x80, 20 zero bytes, 0x80, 0x80, 0x80, 0x80])])
			name:           "zero value",
			raw:            "0xdbda8094000000000000000000000000000000000000000080808080",
			authorizations: AuthorizationList{{}},
		},
		{
			name:           "empty list",
			raw:            "0xc0",
			authorizations: AuthorizationList{},
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			raw := hexBytes(t, testCase.raw)

			assert.Equal(t, raw, testCase.authorizations.toRLP())

			list, err := ethrlp.DecodeBytes(raw)
			require.NoError(t, err)

			items, ok := list.GetValue().([]ethrlp.Value)
			require.True(t, ok)
			require.Len(t, items, len(testCase.authorizations))

			decoded := make(AuthorizationList, 0, len(items))

			for _, item := range items {
				values, ok := item.GetValue().([]ethrlp.Value)
				require.True(t, ok)

				var authorization Authorization

				require.NoError(t, authorization.fromRLPValues(values))

				decoded = append(decoded, authorization)
			}

			assert.Equal(t, raw, decoded.toRLP())
		})
	}
}

func TestAuthorizationFromRLPValuesRejects(t *testing.T) {
	t.Parallel()

	// authorization returns the items of a valid authorization,
	// with item i replaced when item is not nil
	authorization := func(i int, item []byte) [][]byte {
		items := [][]byte{
			ethrlp.EncodeUint(1), // chain ID
			ethrlp.EncodeBytes(StringToAddress("0x03").ToBytes()), // address
			ethrlp.EncodeUint(1), // nonce
			ethrlp.EncodeUint(1), // y parity
			ethrlp.EncodeUint(1), // r
			ethrlp.EncodeUint(1), // s
		}

		if item != nil {
			items[i] = item
		}

		return items
	}

	// decode decodes the authorization items into an Authorization
	decode := func(t *testing.T, items [][]byte) error {
		t.Helper()

		list, err := ethrlp.DecodeBytes(ethrlp.EncodeArray(items))
		require.NoError(t, err)

		values, ok := list.GetValue().([]ethrlp.Value)
		require.True(t, ok)

		return (&Authorization{}).fromRLPValues(values)
	}

	require.NoError(t, decode(t, authorization(0, nil)))

	testTable := []struct {
		wantErr error
		name    string
		items   [][]byte
	}{
		{name: "too few items", items: authorization(0, nil)[:5]},
		{name: "too many items", items: append(authorization(0, nil), ethrlp.EncodeUint(1))},
		{
			name:    "33-byte chain ID",
			items:   authorization(0, ethrlp.EncodeBytes(append([]byte{0x01}, make([]byte, 32)...))),
			wantErr: ErrInvalidRLPChainID,
		},
		{
			name:    "chain ID with a leading zero",
			items:   authorization(0, ethrlp.EncodeBytes([]byte{0x00, 0x01})),
			wantErr: ErrInvalidRLPChainID,
		},
		{
			name:    "short address",
			items:   authorization(1, ethrlp.EncodeBytes(make([]byte, 19))),
			wantErr: ErrInvalidRLPAuthorizationAddress,
		},
		{
			name:    "long address",
			items:   authorization(1, ethrlp.EncodeBytes(make([]byte, 21))),
			wantErr: ErrInvalidRLPAuthorizationAddress,
		},
		{name: "address as a list", items: authorization(1, ethrlp.EncodeArray(nil))},
		{
			name:    "9-byte nonce",
			items:   authorization(2, ethrlp.EncodeBytes(bytes.Repeat([]byte{0x01}, 9))),
			wantErr: ErrInvalidRLPNonce,
		},
		{
			name:    "2-byte y parity",
			items:   authorization(3, ethrlp.EncodeBytes([]byte{0x01, 0x00})),
			wantErr: ErrInvalidRLPYParity,
		},
		{
			name:    "33-byte r",
			items:   authorization(4, ethrlp.EncodeBytes(append([]byte{0x01}, make([]byte, 32)...))),
			wantErr: ErrInvalidRLPRParam,
		},
		{
			name:    "s with a leading zero",
			items:   authorization(5, ethrlp.EncodeBytes([]byte{0x00, 0x01})),
			wantErr: ErrInvalidRLPSParam,
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := decode(t, testCase.items)
			if testCase.wantErr == nil {
				assert.Error(t, err)

				return
			}

			assert.ErrorIs(t, err, testCase.wantErr)
		})
	}
}

func TestAuthorizationListProto(t *testing.T) {
	t.Parallel()

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()

		// Mainnet block 26364325 (Osaka), tx 0x7a5a82345b57a178c566008b0bd49fb240a31b9d253f7a4fe145861aab4d2054
		authorizations := AuthorizationList{
			{
				ChainID: big.NewInt(1),
				YParity: big.NewInt(1),
				R:       bigHex(t, "0xe4c73108b381a4ff6f94b90792466649e53278da479391958d055514e3f1b452"),
				S:       bigHex(t, "0x1fd74be7e6ed80c819c5942a245d2e09fc8a943fc718fe901915174569d05256"),
				Address: StringToAddress("0x84d05511614272694d3a9cebe896514dbde51f40"),
				Nonce:   0xa2b4c,
			},
		}

		decoded, err := authorizationListFromProto(authorizations.toProto())
		require.NoError(t, err)

		assert.Equal(t, authorizations.toRLP(), decoded.toRLP())
	})

	t.Run("empty list", func(t *testing.T) {
		t.Parallel()

		decoded, err := authorizationListFromProto(nil)
		require.NoError(t, err)

		assert.Empty(t, decoded)
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()

		testTable := []struct {
			name           string
			authorizations []*txProto.Authorization
		}{
			{name: "nil authorization", authorizations: []*txProto.Authorization{nil}},
			{name: "empty address", authorizations: []*txProto.Authorization{{}}},
			{name: "short proto address", authorizations: []*txProto.Authorization{{Address: make([]byte, 19)}}},
			{name: "long proto address", authorizations: []*txProto.Authorization{{Address: make([]byte, 21)}}},
		}

		for _, testCase := range testTable {
			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				_, err := authorizationListFromProto(testCase.authorizations)
				assert.Error(t, err)
			})
		}
	})
}
