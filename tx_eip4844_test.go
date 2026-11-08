package ethtypes

import (
	"math/big"
	"testing"

	"github.com/sig-0/ethrlp"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTxEIP4844Encode(t *testing.T) {
	t.Parallel()

	t.Run("round trips", func(t *testing.T) {
		t.Parallel()

		tx := &TxEIP4844{
			ChainID:              big.NewInt(1),
			MaxPriorityFeePerGas: big.NewInt(2),
			MaxFeePerGas:         big.NewInt(3),
			MaxFeePerBlobGas:     big.NewInt(4),
			Value:                big.NewInt(5),
			YParity:              big.NewInt(1),
			R:                    big.NewInt(6),
			S:                    big.NewInt(7),
			Data:                 []byte{0xde, 0xad},
			AccessList: AccessList{
				{Address: StringToAddress("0x01"), StorageKeys: []Hash{StringToHash("0x02"), StringToHash("0x03")}},
				{Address: StringToAddress("0x04"), StorageKeys: []Hash{StringToHash("0x05")}},
			},
			BlobVersionedHashes: []Hash{StringToHash("0x0106"), StringToHash("0x0107")},
			To:                  StringToAddress("0x08"),
			Nonce:               9,
			Gas:                 10,
		}
		signed := tx.ToSignedRLP()

		fromProto := &TxEIP4844{}
		require.NoError(t, fromProto.FromProto(tx.ToProto()))
		assert.Equal(t, signed, fromProto.ToSignedRLP())

		// Decoding the same proto again into the same receiver does not append
		require.NoError(t, fromProto.FromProto(tx.ToProto()))
		assert.Equal(t, signed, fromProto.ToSignedRLP())

		fromRLP := &TxEIP4844{}
		require.NoError(t, fromRLP.FromRLP(signed[1:]))
		assert.Equal(t, signed, fromRLP.ToSignedRLP())
	})

	t.Run("zero value", func(t *testing.T) {
		t.Parallel()

		tx := &TxEIP4844{}

		// Nil big ints encode as 0x80, to as 20 zero bytes, both lists as 0xc0
		assert.Equal(t, hexBytes(t, "0x03df80808080809400000000000000000000000000000000000000008080c080c0"), tx.ToRLP())
		assert.Equal(t, hexBytes(t, "0x03e280808080809400000000000000000000000000000000000000008080c080c0808080"), tx.ToSignedRLP())
		assert.NotPanics(t, func() { tx.ToProto() })
	})
}

func TestTxEIP4844FromRLPRejects(t *testing.T) {
	t.Parallel()

	// Mainnet block 19426589, tx 0x9c1fbda4f649ac806ab0faefbe94e1a60282eb374ead6aa01bac042f52b28a8c
	var valid TxEIP4844
	require.NoError(t, valid.FromRLP(hexBytes(t, "0x03f8930180843b9aca008601d1e4e4ea008252089400000000000000000000000000000000000000008080c0843b9aca00e1a00175f564b393e44640ecffddce4010a42c1c966413987d8a59a253ef64a0c5cf01a04169d4bf9df18182d86715d4ec031c20aded1a4a2613f57e0c0169e16cf763c2a006fc81d18602b8a1e065193488a7c943dfd780adb7b72dfc332de7d68605986e")[1:]))

	// signedFields returns the RLP encoded fields of the valid signed tx
	signedFields := func() [][]byte {
		return [][]byte{
			ethrlp.EncodeBytes(valid.ChainID.Bytes()),
			ethrlp.EncodeUint(valid.Nonce),
			ethrlp.EncodeBytes(valid.MaxPriorityFeePerGas.Bytes()),
			ethrlp.EncodeBytes(valid.MaxFeePerGas.Bytes()),
			ethrlp.EncodeUint(valid.Gas),
			ethrlp.EncodeBytes(valid.To.ToBytes()),
			ethrlp.EncodeBytes(valid.Value.Bytes()),
			ethrlp.EncodeBytes(valid.Data),
			valid.AccessList.ToRLP(),
			ethrlp.EncodeBytes(valid.MaxFeePerBlobGas.Bytes()),
			ethrlp.EncodeArray([][]byte{ethrlp.EncodeBytes(valid.BlobVersionedHashes[0].ToBytes())}),
			ethrlp.EncodeBytes(valid.YParity.Bytes()),
			ethrlp.EncodeBytes(valid.R.Bytes()),
			ethrlp.EncodeBytes(valid.S.Bytes()),
		}
	}

	// The fields re-encode to the valid payload
	require.Equal(t, valid.ToSignedRLP()[1:], ethrlp.EncodeArray(signedFields()))

	// signedPayload replaces item i of the signed field list and encodes it without the type byte
	signedPayload := func(i int, item []byte) []byte {
		fields := signedFields()
		fields[i] = item

		return ethrlp.EncodeArray(fields)
	}

	testTable := []struct {
		wantErr error
		name    string
		payload []byte
	}{
		{
			name:    "empty to",
			payload: signedPayload(5, ethrlp.EncodeBytes(nil)),
			wantErr: ErrInvalidRLPTo,
		},
		{
			name:    "31-byte blob hash",
			payload: signedPayload(10, ethrlp.EncodeArray([][]byte{ethrlp.EncodeBytes(make([]byte, 31))})),
			wantErr: ErrInvalidRLPBlobVersionedHashes,
		},
		{
			// A type mismatch has no sentinel, only the "invalid RLP encoding type" message
			name:    "blob hash list as a string",
			payload: signedPayload(10, ethrlp.EncodeBytes(make([]byte, 32))),
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := (&TxEIP4844{}).FromRLP(testCase.payload)
			if testCase.wantErr == nil {
				assert.Error(t, err)

				return
			}

			assert.ErrorIs(t, err, testCase.wantErr)
		})
	}

	t.Run("13 items", func(t *testing.T) {
		t.Parallel()

		assert.Error(t, (&TxEIP4844{}).FromRLP(ethrlp.EncodeArray(signedFields()[:13])))
	})

	t.Run("proto", func(t *testing.T) {
		t.Parallel()

		eip1559 := &txProto.Transaction{Payload: &txProto.Transaction_Eip1559{Eip1559: &txProto.EIP1559{}}}

		assert.ErrorIs(t, (&TxEIP4844{}).FromProto(nil), ErrNilProtoTx)
		assert.ErrorIs(t, (&TxEIP4844{}).FromProto(eip1559), ErrInvalidProtoEIP4844Tx)
	})
}
