package ethtypes

import (
	"math/big"
	"testing"

	"github.com/sig-0/ethrlp"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTxEIP7702Encode(t *testing.T) {
	t.Parallel()

	t.Run("zero values", func(t *testing.T) {
		t.Parallel()

		for _, tx := range []*TxEIP7702{{}, {AuthorizationList: AuthorizationList{{}}}} {
			assert.NotPanics(t, func() {
				tx.ToRLP()
				tx.ToSignedRLP()
				tx.ToProto()
			})
		}
	})

	t.Run("empty authorization list", func(t *testing.T) {
		t.Parallel()

		tx := &TxEIP7702{ChainID: big.NewInt(1), To: StringToAddress("0x01")}
		signed := tx.ToSignedRLP()

		assert.Equal(t, []byte{0xc0}, tx.AuthorizationList.toRLP())

		fromRLP := &TxEIP7702{}
		require.NoError(t, fromRLP.FromRLP(signed[1:]))
		assert.Equal(t, signed, fromRLP.ToSignedRLP())

		fromProto := &TxEIP7702{}
		require.NoError(t, fromProto.FromProto(tx.ToProto()))
		assert.Equal(t, signed, fromProto.ToSignedRLP())
	})

	t.Run("mainnet type 4 proto round trip", func(t *testing.T) {
		t.Parallel()

		// Mainnet block 26364325 (Osaka), tx 0x7a5a82345b57a178c566008b0bd49fb240a31b9d253f7a4fe145861aab4d2054
		raw := hexBytes(t, "0x04f8f301830295c38401ae67e9840443663983010f2c944de23f3f0fb3318287378adbde030cf61714b2f380a4c4d66de8000000000000000000000000333333320bb4a0345a7a102c49c72b37647aa088c0f85ff85d019484d05511614272694d3a9cebe896514dbde51f40830a2b4c01a0e4c73108b381a4ff6f94b90792466649e53278da479391958d055514e3f1b452a01fd74be7e6ed80c819c5942a245d2e09fc8a943fc718fe901915174569d0525680a04268b8d89e73a07e07e90a2e2ec9144192b2d462f7a38dc42f35e626227ce3e2a06dec9a66d710a721cdbd808866812b020cd36cc5c215f19f38fa0c892db7b41d")
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

		tx, err := decodeRawTx(raw)
		require.NoError(t, err)

		pb, err := tx.ToProto()
		require.NoError(t, err)

		decoded := &Transaction{}
		require.NoError(t, decoded.FromProto(pb))

		signed, err := decoded.ToSignedRLP()
		require.NoError(t, err)
		assert.Equal(t, raw, signed)
		assert.Equal(t, authorizations.toRLP(), decoded.AuthorizationList().toRLP())
	})
}

func TestTxEIP7702FromRLPRejects(t *testing.T) {
	t.Parallel()

	to := StringToAddress("0x02").ToBytes()

	// validAuthorization returns the items of a valid authorization,
	// with item i replaced when item is not nil
	validAuthorization := func(i int, item []byte) [][]byte {
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

	// signedPayload encodes a signed set-code tx without the type byte
	signedPayload := func(authorization [][]byte, to []byte) []byte {
		return ethrlp.EncodeArray([][]byte{
			ethrlp.EncodeUint(0),    // chain ID
			ethrlp.EncodeUint(0),    // nonce
			ethrlp.EncodeUint(0),    // max priority fee per gas
			ethrlp.EncodeUint(0),    // max fee per gas
			ethrlp.EncodeUint(0),    // gas limit
			ethrlp.EncodeBytes(to),  // to
			ethrlp.EncodeUint(0),    // value
			ethrlp.EncodeBytes(nil), // data
			ethrlp.EncodeArray(nil), // access list
			ethrlp.EncodeArray([][]byte{ethrlp.EncodeArray(authorization)}), // authorization list
			ethrlp.EncodeUint(0), // y parity
			ethrlp.EncodeUint(1), // r
			ethrlp.EncodeUint(1), // s
		})
	}

	require.NoError(t, (&TxEIP7702{}).FromRLP(signedPayload(validAuthorization(0, nil), to)))

	testTable := []struct {
		wantErr error
		name    string
		payload []byte
	}{
		{
			name:    "2-byte y parity",
			payload: signedPayload(validAuthorization(3, ethrlp.EncodeBytes([]byte{0x01, 0x00})), to),
			wantErr: ErrInvalidRLPAuthorizationList,
		},
		{
			name:    "33-byte chain ID",
			payload: signedPayload(validAuthorization(0, ethrlp.EncodeBytes(append([]byte{0x01}, make([]byte, 32)...))), to),
			wantErr: ErrInvalidRLPAuthorizationList,
		},
		{
			name:    "5 items",
			payload: signedPayload(validAuthorization(0, nil)[:5], to),
			wantErr: ErrInvalidRLPAuthorizationList,
		},
		{
			name:    "authorization address of 19 bytes",
			payload: signedPayload(validAuthorization(1, ethrlp.EncodeBytes(make([]byte, 19))), to),
			wantErr: ErrInvalidRLPAuthorizationList,
		},
		{
			name:    "empty to",
			payload: signedPayload(validAuthorization(0, nil), nil),
			wantErr: ErrInvalidRLPTo,
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			assert.ErrorIs(t, (&TxEIP7702{}).FromRLP(testCase.payload), testCase.wantErr)
		})
	}

	t.Run("proto of another type", func(t *testing.T) {
		t.Parallel()

		eip4844 := &txProto.Transaction{Payload: &txProto.Transaction_Eip4844{Eip4844: &txProto.EIP4844{}}}

		assert.ErrorIs(t, (&TxEIP7702{}).FromProto(eip4844), ErrInvalidProtoEIP7702Tx)
	})
}
