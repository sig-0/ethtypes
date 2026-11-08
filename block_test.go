package ethtypes

import (
	"math/big"
	"testing"

	"github.com/sig-0/ethrlp"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBlock builds a block from a header and raw EIP-2718 transaction envelopes
func newTestBlock(t *testing.T, header headerData, rawTxs [][]byte, withdrawals []Withdrawal) *Block {
	t.Helper()

	txs := make([]*Transaction, 0, len(rawTxs))

	for _, raw := range rawTxs {
		tx, err := decodeRawTx(raw)
		require.NoError(t, err)

		txs = append(txs, tx)
	}

	return &Block{Header: NewHeader(header), Transactions: txs, Withdrawals: withdrawals}
}

// protoRoundTrip converts the block to proto and back
func protoRoundTrip(t *testing.T, block *Block) *Block {
	t.Helper()

	pb, err := block.ToProto()
	require.NoError(t, err)

	got := &Block{}
	require.NoError(t, got.FromProto(pb))

	return got
}

func TestBlockSpecVectors(t *testing.T) {
	t.Parallel()

	// The transaction of every block_intermediate_state block before Osaka
	const (
		intermediateStateTx     = "0xf84d800a8407270e008080801ca0c541bc5e0babce3edb49cf49f57f51f546a50914d53177aaac4c4345efa9783ea0412cd87f12d177d860a906a989b8e6f677745b000c51e4163f04757c95ea2046"
		intermediateStateTxHash = "0x07dd9f5acaf8a2996abb6c19f69b7fe36ad347d7199ad3ce3234c3af307d7fd0"
	)

	// Withdrawal from the shanghaiExample_Prague spec block
	shanghaiWithdrawal := Withdrawal{Address: StringToAddress("0xc94f5374fce5edbc8e2a8697c15331677e6ebf0b"), Amount: 10000}
	assert.Equal(t, hexBytes(t, "0xda808094c94f5374fce5edbc8e2a8697c15331677e6ebf0b822710"), shanghaiWithdrawal.ToRLP())

	testTable := []struct {
		header      headerData
		name        string
		txs         [][]byte
		txHashes    []Hash
		withdrawals []Withdrawal
		rlp         []byte
		size        int
		hash        Hash
	}{
		{
			// EEST tests@v21.0.2 fixtures/blockchain_tests/for_frontier/frontier/examples/block_intermediate_state/block_intermediate_state.json, test tests/frontier/examples/test_block_intermediate_state.py::test_block_intermediate_state[fork_Frontier-blockchain_test]
			name: "frontier intermediate state",
			header: &HeaderLegacy{
				ParentHash:       StringToHash("0x60dfd45f6218c72e960e77b30c3e6bd5d1aee9f00bded49be9cccf273e9348fa"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
				StateRoot:        StringToHash("0x20717e8663ea541cc7f18eef7005637564c089599562da31e8260a47e58e763f"),
				TransactionsRoot: StringToHash("0x63b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11e"),
				ReceiptsRoot:     StringToHash("0xc1adca4afba7f5b72424528c2bacf8d447a6c61a9b220e8446984e0fa90fa8e9"),
				Difficulty:       0x20040,
				Number:           0x1,
				GasLimit:         0x7270e00,
				GasUsed:          0x5208,
				Timestamp:        0xc,
			},
			txs:      [][]byte{hexBytes(t, intermediateStateTx)},
			txHashes: []Hash{StringToHash(intermediateStateTxHash)},
			rlp:      hexBytes(t, "0xf9024bf901f6a060dfd45f6218c72e960e77b30c3e6bd5d1aee9f00bded49be9cccf273e9348faa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa020717e8663ea541cc7f18eef7005637564c089599562da31e8260a47e58e763fa063b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11ea0c1adca4afba7f5b72424528c2bacf8d447a6c61a9b220e8446984e0fa90fa8e9b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000083020040018407270e008252080c80a00000000000000000000000000000000000000000000000000000000000000000880000000000000000f84ff84d800a8407270e008080801ca0c541bc5e0babce3edb49cf49f57f51f546a50914d53177aaac4c4345efa9783ea0412cd87f12d177d860a906a989b8e6f677745b000c51e4163f04757c95ea2046c0"),
			size:     590,
			hash:     StringToHash("0x501b6dd7c525075079a474016ed5e87d37af896ff77c9acc35d3250bdeb5be1b"),
		},
		{
			// EEST tests@v21.0.2 fixtures/blockchain_tests/for_london/frontier/examples/block_intermediate_state/block_intermediate_state.json, test tests/frontier/examples/test_block_intermediate_state.py::test_block_intermediate_state[fork_London-blockchain_test]
			name: "london intermediate state",
			header: &HeaderEIP1559{
				ParentHash:       StringToHash("0xd184664ec8297445cab48aae600f8ab319ff91c1fc1002d44c6840c1335fecfe"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
				StateRoot:        StringToHash("0xce549a89f49e677c17e9fdd013b3a2d9c2919dd31dca649a6cb08683dacced05"),
				TransactionsRoot: StringToHash("0x63b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11e"),
				ReceiptsRoot:     StringToHash("0x65c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bf"),
				Difficulty:       0x20000,
				Number:           0x1,
				GasLimit:         0x7270e00,
				GasUsed:          0xcf08,
				Timestamp:        0xc,
				BaseFeePerGas:    big.NewInt(0x7),
			},
			txs:      [][]byte{hexBytes(t, intermediateStateTx)},
			txHashes: []Hash{StringToHash(intermediateStateTxHash)},
			rlp:      hexBytes(t, "0xf9024cf901f7a0d184664ec8297445cab48aae600f8ab319ff91c1fc1002d44c6840c1335fecfea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0ce549a89f49e677c17e9fdd013b3a2d9c2919dd31dca649a6cb08683dacced05a063b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11ea065c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bfb901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000083020000018407270e0082cf080c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007f84ff84d800a8407270e008080801ca0c541bc5e0babce3edb49cf49f57f51f546a50914d53177aaac4c4345efa9783ea0412cd87f12d177d860a906a989b8e6f677745b000c51e4163f04757c95ea2046c0"),
			size:     591,
			hash:     StringToHash("0x1b8c51513d0834effd565442cbd345047e5ac14daa7f715889a0ec1e405ca270"),
		},
		{
			// EEST tests@v21.0.2 fixtures/blockchain_tests/for_paris/frontier/examples/block_intermediate_state/block_intermediate_state.json, test tests/frontier/examples/test_block_intermediate_state.py::test_block_intermediate_state[fork_Paris-blockchain_test]
			name: "paris intermediate state",
			header: &HeaderEIP1559{
				ParentHash:       StringToHash("0x2abc4d1ea5133c205a19f9001e9f9c20e2289c32e2fdcc4fb3a0581b6032531e"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
				StateRoot:        StringToHash("0x515ccbbcab773a6e3ee7dcdd70eab8d717fc9bd5d567b5741eb6a514720e0d5c"),
				TransactionsRoot: StringToHash("0x63b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11e"),
				ReceiptsRoot:     StringToHash("0x65c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bf"),
				Number:           0x1,
				GasLimit:         0x7270e00,
				GasUsed:          0xcf08,
				Timestamp:        0xc,
				BaseFeePerGas:    big.NewInt(0x7),
			},
			txs:      [][]byte{hexBytes(t, intermediateStateTx)},
			txHashes: []Hash{StringToHash(intermediateStateTxHash)},
			rlp:      hexBytes(t, "0xf90249f901f4a02abc4d1ea5133c205a19f9001e9f9c20e2289c32e2fdcc4fb3a0581b6032531ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0515ccbbcab773a6e3ee7dcdd70eab8d717fc9bd5d567b5741eb6a514720e0d5ca063b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11ea065c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bfb901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e0082cf080c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007f84ff84d800a8407270e008080801ca0c541bc5e0babce3edb49cf49f57f51f546a50914d53177aaac4c4345efa9783ea0412cd87f12d177d860a906a989b8e6f677745b000c51e4163f04757c95ea2046c0"),
			size:     588,
			hash:     StringToHash("0xde932b771fde24f047a68297e55bbbd66e066e45fa5c8dbc9a83559a573a6888"),
		},
		{
			// EEST tests@v21.0.2 fixtures/blockchain_tests/for_shanghai/frontier/examples/block_intermediate_state/block_intermediate_state.json, test tests/frontier/examples/test_block_intermediate_state.py::test_block_intermediate_state[fork_Shanghai-blockchain_test]
			name: "shanghai intermediate state",
			header: &HeaderEIP4895{
				ParentHash:       StringToHash("0xc366e78bb27dbb6a3c7a2256ddaf14c3c12b5d5ab1236cb35fa6ce129a8d2ba6"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
				StateRoot:        StringToHash("0x515ccbbcab773a6e3ee7dcdd70eab8d717fc9bd5d567b5741eb6a514720e0d5c"),
				TransactionsRoot: StringToHash("0x63b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11e"),
				ReceiptsRoot:     StringToHash("0x65c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bf"),
				Number:           0x1,
				GasLimit:         0x7270e00,
				GasUsed:          0xcf08,
				Timestamp:        0xc,
				BaseFeePerGas:    big.NewInt(0x7),
				WithdrawalsRoot:  ZeroStorageHash,
			},
			txs:      [][]byte{hexBytes(t, intermediateStateTx)},
			txHashes: []Hash{StringToHash(intermediateStateTxHash)},
			rlp:      hexBytes(t, "0xf9026bf90215a0c366e78bb27dbb6a3c7a2256ddaf14c3c12b5d5ab1236cb35fa6ce129a8d2ba6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0515ccbbcab773a6e3ee7dcdd70eab8d717fc9bd5d567b5741eb6a514720e0d5ca063b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11ea065c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bfb901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e0082cf080c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421f84ff84d800a8407270e008080801ca0c541bc5e0babce3edb49cf49f57f51f546a50914d53177aaac4c4345efa9783ea0412cd87f12d177d860a906a989b8e6f677745b000c51e4163f04757c95ea2046c0c0"),
			size:     622,
			hash:     StringToHash("0x9b37de422afe0a49c5d2d3e553f1bdb76271b9e85ccf4911b9f45344d7d3f92f"),
		},
		{
			// EEST tests@v21.0.2 fixtures/blockchain_tests/for_cancun/frontier/examples/block_intermediate_state/block_intermediate_state.json, test tests/frontier/examples/test_block_intermediate_state.py::test_block_intermediate_state[fork_Cancun-blockchain_test]
			name: "cancun intermediate state",
			header: &HeaderEIP4844{
				ParentHash:       StringToHash("0x09099c09f736f55edbaf5b645559fb142a22490c04e60a63c817f24b7e237be4"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
				StateRoot:        StringToHash("0x0ab5c0694d9797560c9c356cdc8f4095c2007aa9c0579004409ed2b1d523490e"),
				TransactionsRoot: StringToHash("0x63b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11e"),
				ReceiptsRoot:     StringToHash("0x65c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bf"),
				Number:           0x1,
				GasLimit:         0x7270e00,
				GasUsed:          0xcf08,
				Timestamp:        0xc,
				BaseFeePerGas:    big.NewInt(0x7),
				WithdrawalsRoot:  ZeroStorageHash,
			},
			txs:      [][]byte{hexBytes(t, intermediateStateTx)},
			txHashes: []Hash{StringToHash(intermediateStateTxHash)},
			rlp:      hexBytes(t, "0xf9028ef90238a009099c09f736f55edbaf5b645559fb142a22490c04e60a63c817f24b7e237be4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa00ab5c0694d9797560c9c356cdc8f4095c2007aa9c0579004409ed2b1d523490ea063b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11ea065c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bfb901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e0082cf080c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000f84ff84d800a8407270e008080801ca0c541bc5e0babce3edb49cf49f57f51f546a50914d53177aaac4c4345efa9783ea0412cd87f12d177d860a906a989b8e6f677745b000c51e4163f04757c95ea2046c0c0"),
			size:     657,
			hash:     StringToHash("0x8da4d7360a2b180b27fe33aa42e889fcf81bdb9116d7e7a84c2e92388355e9a3"),
		},
		{
			// EEST tests@v21.0.2 fixtures/blockchain_tests/for_prague/frontier/examples/block_intermediate_state/block_intermediate_state.json, test tests/frontier/examples/test_block_intermediate_state.py::test_block_intermediate_state[fork_Prague-blockchain_test]
			name: "prague intermediate state",
			header: &HeaderEIP7685{
				ParentHash:       StringToHash("0xabe85ae73b2a9e80f02ed1f5316613a6291d5339ebd5594fdb544048d5d854a2"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
				StateRoot:        StringToHash("0x7a22a54eb48d0d952deac56ea0c58a4cb4af5f4b7ff00e1590b485938f51a842"),
				TransactionsRoot: StringToHash("0x63b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11e"),
				ReceiptsRoot:     StringToHash("0x65c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bf"),
				Number:           0x1,
				GasLimit:         0x7270e00,
				GasUsed:          0xcf08,
				Timestamp:        0xc,
				BaseFeePerGas:    big.NewInt(0x7),
				WithdrawalsRoot:  ZeroStorageHash,
				RequestsHash:     StringToHash("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
			txs:      [][]byte{hexBytes(t, intermediateStateTx)},
			txHashes: []Hash{StringToHash(intermediateStateTxHash)},
			rlp:      hexBytes(t, "0xf902aff90259a0abe85ae73b2a9e80f02ed1f5316613a6291d5339ebd5594fdb544048d5d854a2a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa07a22a54eb48d0d952deac56ea0c58a4cb4af5f4b7ff00e1590b485938f51a842a063b6b52c158432809365c8c8fe30da46c2923fc6c70694d4bc4e0cf127d0e11ea065c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bfb901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e0082cf080c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f84ff84d800a8407270e008080801ca0c541bc5e0babce3edb49cf49f57f51f546a50914d53177aaac4c4345efa9783ea0412cd87f12d177d860a906a989b8e6f677745b000c51e4163f04757c95ea2046c0c0"),
			size:     690,
			hash:     StringToHash("0x7842c365c3dd91347261c173e953494feb944f31b6113ceb13b5224b8b50cb68"),
		},
		{
			// EEST tests@v21.0.2 fixtures/blockchain_tests/for_osaka/frontier/examples/block_intermediate_state/block_intermediate_state.json, test tests/frontier/examples/test_block_intermediate_state.py::test_block_intermediate_state[fork_Osaka-blockchain_test]
			name: "osaka intermediate state",
			header: &HeaderEIP7685{
				ParentHash:       StringToHash("0xabe85ae73b2a9e80f02ed1f5316613a6291d5339ebd5594fdb544048d5d854a2"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
				StateRoot:        StringToHash("0x7a22a54eb48d0d952deac56ea0c58a4cb4af5f4b7ff00e1590b485938f51a842"),
				TransactionsRoot: StringToHash("0xc3b9a29a047ee78b8c79936b374566a70fc73dbc9e117b30d8ee1014ddad5f76"),
				ReceiptsRoot:     StringToHash("0x65c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bf"),
				Number:           0x1,
				GasLimit:         0x7270e00,
				GasUsed:          0xcf08,
				Timestamp:        0xc,
				BaseFeePerGas:    big.NewInt(0x7),
				WithdrawalsRoot:  ZeroStorageHash,
				RequestsHash:     StringToHash("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
			txs:      [][]byte{hexBytes(t, "0xf84d800a84010000008080801ba0aeb2403cf9f2400e41c3093ff1f72f8b8555a114389364deb107638b1818e6cfa0320747229db6bba2e776c37a866f7a2052f841e30d795e62c945d9b4093c9fa7")},
			txHashes: []Hash{StringToHash("0xdd499bebe161e3dde406145a5cdb8db76b7ce190ead52c8b5f1a34a93592b8ca")},
			rlp:      hexBytes(t, "0xf902aff90259a0abe85ae73b2a9e80f02ed1f5316613a6291d5339ebd5594fdb544048d5d854a2a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa07a22a54eb48d0d952deac56ea0c58a4cb4af5f4b7ff00e1590b485938f51a842a0c3b9a29a047ee78b8c79936b374566a70fc73dbc9e117b30d8ee1014ddad5f76a065c4d1b533902562730f0d110bcce51643ce4725ca03d85c33d5812c0ed308bfb901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e0082cf080c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f84ff84d800a84010000008080801ba0aeb2403cf9f2400e41c3093ff1f72f8b8555a114389364deb107638b1818e6cfa0320747229db6bba2e776c37a866f7a2052f841e30d795e62c945d9b4093c9fa7c0c0"),
			size:     690,
			hash:     StringToHash("0xa8c663a6952ba2b66511bdbfed12ec0f2557d19c1725ecbaf8a2d159ef3a5380"),
		},
		{
			// EEST tests@v21.0.2 fixtures/blockchain_tests/for_prague/prague/eip7702_set_code_tx/set_code_txs/valid_tx_invalid_auth_signature.json, test tests/prague/eip7702_set_code_tx/test_set_code_txs.py::test_valid_tx_invalid_auth_signature[fork_Prague-blockchain_test_from_state_test-r=0]
			name: "prague type 4",
			header: &HeaderEIP7685{
				ParentHash:       StringToHash("0xd39f62d8f6780b542bd409d095050a4fef1a472ea7c7a72cdeee5d948452f59b"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
				StateRoot:        StringToHash("0x6f24fc5b47c7dcab6eb1168fc5188fe754290284e1c0a7fe23c70ed01d4e8b2f"),
				TransactionsRoot: StringToHash("0x718d214297c28da9da2bee162c0677c6287bef379828338ef63241523564c659"),
				ReceiptsRoot:     StringToHash("0x5719ea416677b09c9070ef0711e2a036fe045f80aaf3f89beddb18c69bda5d6d"),
				Number:           0x1,
				GasLimit:         0x7270e00,
				GasUsed:          0x10a0a,
				Timestamp:        0x3e8,
				ExtraData:        hexBytes(t, "0x00"),
				BaseFeePerGas:    big.NewInt(0x7),
				WithdrawalsRoot:  ZeroStorageHash,
				RequestsHash:     StringToHash("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
			txs:      [][]byte{hexBytes(t, "0x04f880018080078407270e00946280aceac5db12798d67870e2447ac01ab4e316a8080c0dbda019400000000000000000000000000000000000000008001800180a04763d5a7011dc615eb6682c7bdb9492bd48cddc3bc59e6a24653cfa031885d98a01cb2b4c89661dbd91f6653c13a55019f5f71061a408f6bd304697e68ee04aacc")},
			txHashes: []Hash{StringToHash("0x7fc57c54ae5bf285886b9c0fac148b1449151133647cb2c4151f7fe9e9ca13d6")},
			rlp:      hexBytes(t, "0xf902e8f9025ca0d39f62d8f6780b542bd409d095050a4fef1a472ea7c7a72cdeee5d948452f59ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa06f24fc5b47c7dcab6eb1168fc5188fe754290284e1c0a7fe23c70ed01d4e8b2fa0718d214297c28da9da2bee162c0677c6287bef379828338ef63241523564c659a05719ea416677b09c9070ef0711e2a036fe045f80aaf3f89beddb18c69bda5d6db901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e0083010a0a8203e800a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f885b88304f880018080078407270e00946280aceac5db12798d67870e2447ac01ab4e316a8080c0dbda019400000000000000000000000000000000000000008001800180a04763d5a7011dc615eb6682c7bdb9492bd48cddc3bc59e6a24653cfa031885d98a01cb2b4c89661dbd91f6653c13a55019f5f71061a408f6bd304697e68ee04aaccc0c0"),
			size:     747,
			hash:     StringToHash("0x0ddc449decafdbdda8578e40af3f19ef3973c59fabbcc9a84702468951414727"),
		},
		{
			// ethereum/tests v17.2 (commit c67e485ff8b5be9abc8ad15345ec21aa22e290d9) BlockchainTests/ValidBlocks/bcExample/shanghaiExample.json, test shanghaiExample_Prague
			name: "shanghai example prague",
			header: &HeaderEIP7685{
				ParentHash:       StringToHash("0x50ee69cad3839d7780586f9a487540412f58e1bdf79bf1954ce537d795981414"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"),
				StateRoot:        StringToHash("0x9798bedc4148c2a471c54b5c7aea9713334a201d6285f22c02e04ce660cd189b"),
				TransactionsRoot: StringToHash("0x71e515dd89e8a7973402c2e11646081b4e2209b2d3a1550df5095289dabcb3fb"),
				ReceiptsRoot:     StringToHash("0xed9c51ea52c968e552e370a77a41dac98606e98b915092fb5f949d6452fce1c4"),
				Number:           0x1,
				GasLimit:         0x7fffffffffffffff,
				GasUsed:          0x125b8,
				Timestamp:        0x79e,
				ExtraData:        hexBytes(t, "0x42"),
				MixDigest:        StringToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
				BaseFeePerGas:    big.NewInt(0x9),
				WithdrawalsRoot:  StringToHash("0x27f166f1d7c789251299535cb176ba34116e44894476a7886fe5d73d9be5c973"),
				RequestsHash:     StringToHash("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
			txs:         [][]byte{hexBytes(t, "0xf852802883061a808080866001600155001ba00b46eb2e2c914b99416e723a37be923605238a81c83c25b5f842544bebea8816a065730cb3fb806bd5260c1db09198459a2a2499e51b43a3780b48c1a3594133f2")},
			txHashes:    []Hash{StringToHash("0x2139b05de62f9b1cbe3e8db073c5361fb6c9cfb5c0e021a492b0dc9d751c1303")},
			withdrawals: []Withdrawal{shanghaiWithdrawal},
			rlp:         hexBytes(t, "0xf902d6f90260a050ee69cad3839d7780586f9a487540412f58e1bdf79bf1954ce537d795981414a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa09798bedc4148c2a471c54b5c7aea9713334a201d6285f22c02e04ce660cd189ba071e515dd89e8a7973402c2e11646081b4e2209b2d3a1550df5095289dabcb3fba0ed9c51ea52c968e552e370a77a41dac98606e98b915092fb5f949d6452fce1c4b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008001887fffffffffffffff830125b882079e42a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42188000000000000000009a027f166f1d7c789251299535cb176ba34116e44894476a7886fe5d73d9be5c9738080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f854f852802883061a808080866001600155001ba00b46eb2e2c914b99416e723a37be923605238a81c83c25b5f842544bebea8816a065730cb3fb806bd5260c1db09198459a2a2499e51b43a3780b48c1a3594133f2c0dbda808094c94f5374fce5edbc8e2a8697c15331677e6ebf0b822710"),
			size:        729,
			hash:        StringToHash("0x6e6538f7eb9e7c7eb1ab8a4444f59cfd66b5d81978609d22b94aad9398ffc10a"),
		},
		{
			// ethereum/tests v17.2 (commit c67e485ff8b5be9abc8ad15345ec21aa22e290d9) BlockchainTests/ValidBlocks/bcEIP4844-blobtransactions/blockWithAllTransactionTypes.json, test blockWithAllTransactionTypes_Prague
			name: "all transaction types prague",
			header: &HeaderEIP7685{
				ParentHash:       StringToHash("0xac0b97dbc3adc94bf90280ba05c0e6ed4b42e8eb34f30d025ced23e91f7b0815"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0xba5e000000000000000000000000000000000000"),
				StateRoot:        StringToHash("0xee70099962031bda4e405812e83d9965983d54a1c67a34e1c73de97e6bce7639"),
				TransactionsRoot: StringToHash("0x5cb644f722e31f9792a8ef6e2a762334e1a862e8b40c1612e1e9507fd7121ef9"),
				ReceiptsRoot:     StringToHash("0x0c82719448356ba6807d6edfcd8e5aea575a5e97f36038ffb3e395749b26d41c"),
				Number:           0x1,
				GasLimit:         0x16345785d8a0000,
				GasUsed:          0x14820,
				Timestamp:        0x79e,
				ExtraData:        hexBytes(t, "0x42"),
				MixDigest:        StringToHash("0x0000000000000000000000000000000000000000000000000000000000020000"),
				BaseFeePerGas:    big.NewInt(0x314),
				WithdrawalsRoot:  ZeroStorageHash,
				BlobGasUsed:      0x20000,
				RequestsHash:     StringToHash("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
			txs: [][]byte{
				hexBytes(t, "0xf864808203e885e8d4a5100094100000000000000000000000000000000000000a01801ca09de4adda6288582a6700dbcd8eb70c0a4a7fc9487d965f7bf22424e0bd121095a01cdb078764cc3770d5db847e99e10333aa7c356247baaf09b03eae04d64e7926"),
				hexBytes(t, "0x01f86601018203e885e8d4a5100094100000000000000000000000000000000000000a0380c080a025090740da12684493e4fb466a3979e365b194e8cf462edf3c2c3be2f130bb2ea034fa18fb4c1bff4d957d72e28535d27f1352517a942aeaca0ed944085f0cd8bb"),
				hexBytes(t, "0x02f8670102018203e885e8d4a5100094100000000000000000000000000000000000000a0580c080a0352a7be5002ce111bc5167f3addf97a75e2e0b810d826af71d2caae18aed284ea065d38f8a5c8948ce706842e8861fb21020b93a4d5e489162a0e6d419a457b735"),
				hexBytes(t, "0x03f8890103018203e885e8d4a5100094100000000000000000000000000000000000000a0780c00ae1a001a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8809f638144c46d5de7a9e630c0e7c5c63ae829ecfd8cc94715d9c29fe17c464de0a06c5fc54c3aa868ba35ef31a4e12431611631ab7bcdceb4214dd273d83f73b5e1"),
			},
			txHashes: []Hash{
				StringToHash("0xa5df46a2eba63a4caa49f4b646a8c5ebcdaab603358a878c76385e140ec2b82a"),
				StringToHash("0xb63d80d97305e1b508617d59177366e4ed72ca38ce0f8cc5de7c22baf800a3d3"),
				StringToHash("0x01f2da1c214988654e2595b804ab288f69a5198ec584cf5ba13e5b5416b8ec2e"),
				StringToHash("0x859f215b2c6d4e57503d8c26e1485432568df6b3aff464cb7e272c163351efa0"),
			},
			rlp:  hexBytes(t, "0xf90438f90265a0ac0b97dbc3adc94bf90280ba05c0e6ed4b42e8eb34f30d025ced23e91f7b0815a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ba5e000000000000000000000000000000000000a0ee70099962031bda4e405812e83d9965983d54a1c67a34e1c73de97e6bce7639a05cb644f722e31f9792a8ef6e2a762334e1a862e8b40c1612e1e9507fd7121ef9a00c82719448356ba6807d6edfcd8e5aea575a5e97f36038ffb3e395749b26d41cb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800188016345785d8a00008301482082079e42a00000000000000000000000000000000000000000000000000000000000020000880000000000000000820314a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218302000080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f901cbf864808203e885e8d4a5100094100000000000000000000000000000000000000a01801ca09de4adda6288582a6700dbcd8eb70c0a4a7fc9487d965f7bf22424e0bd121095a01cdb078764cc3770d5db847e99e10333aa7c356247baaf09b03eae04d64e7926b86901f86601018203e885e8d4a5100094100000000000000000000000000000000000000a0380c080a025090740da12684493e4fb466a3979e365b194e8cf462edf3c2c3be2f130bb2ea034fa18fb4c1bff4d957d72e28535d27f1352517a942aeaca0ed944085f0cd8bbb86a02f8670102018203e885e8d4a5100094100000000000000000000000000000000000000a0580c080a0352a7be5002ce111bc5167f3addf97a75e2e0b810d826af71d2caae18aed284ea065d38f8a5c8948ce706842e8861fb21020b93a4d5e489162a0e6d419a457b735b88c03f8890103018203e885e8d4a5100094100000000000000000000000000000000000000a0780c00ae1a001a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8809f638144c46d5de7a9e630c0e7c5c63ae829ecfd8cc94715d9c29fe17c464de0a06c5fc54c3aa868ba35ef31a4e12431611631ab7bcdceb4214dd273d83f73b5e1c0c0"),
			size: 1083,
			hash: StringToHash("0x0dd4bc74142c95988047c772a3ed28ccbca0df86bab0edfb8be881cb6f5f061e"),
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			block := newTestBlock(t, testCase.header, testCase.txs, testCase.withdrawals)

			got, err := block.ToRLP()
			require.NoError(t, err)
			assert.Equal(t, testCase.rlp, got)
			assert.Len(t, got, testCase.size)
			assert.Equal(t, testCase.hash, block.Header.Hash())

			require.Len(t, block.Transactions, len(testCase.txHashes))

			for i, tx := range block.Transactions {
				txHash, err := tx.TxHash()
				require.NoError(t, err)
				assert.Equal(t, testCase.txHashes[i], txHash)
			}

			roundTripped, err := protoRoundTrip(t, block).ToRLP()
			require.NoError(t, err)
			assert.Equal(t, testCase.rlp, roundTripped)
		})
	}
}

func TestBlockMainnetSize(t *testing.T) {
	t.Parallel()

	// Recipient of every withdrawal in mainnet block 17036342
	recipient := StringToAddress("0xb9d7934878b5fb9610b3fe8a5e441e8fad7e293f")

	// Headers, uncles, withdrawals and sizes are from eth_getBlockByNumber and
	// eth_getUncleByBlockNumberAndIndex (https://ethereum-rpc.publicnode.com)
	testTable := []struct {
		header      headerData
		name        string
		uncles      []headerData
		uncleHashes []Hash
		txs         [][]byte
		withdrawals []Withdrawal
		size        int
		hash        Hash
	}{
		{
			// Mainnet block 46147, tx 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060
			name: "46147 legacy tx",
			hash: StringToHash("0x4e3a3754410177e6937ef1f84bba68ea139e8d1a2258c5f85db9f1cd715a1bdd"),
			size: 634,
			header: &HeaderLegacy{
				ParentHash:       StringToHash("0x5a41d0e66b4120775176c09fcf39e7c0520517a13d2b57b18d33d342df038bfc"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0xe6a7a1d47ff21b6321162aea7c6cb457d5476bca"),
				StateRoot:        StringToHash("0x0e0df2706b0a4fb8bd08c9246d472abbe850af446405d9eba1db41db18b4a169"),
				TransactionsRoot: StringToHash("0x4513310fcb9f6f616972a3b948dc5d547f280849a87ebb5af0191f98b87be598"),
				ReceiptsRoot:     StringToHash("0xfe2bf2a941abf41d72637e5b91750332a30283efd40c424dc522b77e6f0ed8c4"),
				Difficulty:       0x153886c1bbd,
				Number:           0xb443,
				GasLimit:         0x520b,
				GasUsed:          0x5208,
				Timestamp:        0x55c42659,
				ExtraData:        hexBytes(t, "0x657468706f6f6c2e6f7267"),
				MixDigest:        StringToHash("0xb48c515a9dde8d346c3337ea520aa995a4738bb595495506125449c1149d6cf4"),
				Nonce:            0xba4f8ecd18aab215,
			},
			txs: [][]byte{hexBytes(t, "0xf86780862d79883d2000825208945df9b87991262f6ba471f09758cde1c0fc1de734827a69801ca088ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0a045e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a")},
		},
		{
			// Mainnet block 3, one uncle (block 1 sibling)
			name: "3 one uncle",
			hash: StringToHash("0x3d6122660cc824376f11ee842f83addc3525e2dd6756b9bcf0affa6aa88cf741"),
			size: 1079,
			header: &HeaderLegacy{
				ParentHash:       StringToHash("0xb495a1d7e6663152ae92708da4843337b958146015a2802f4193a410044698c9"),
				UncleHash:        StringToHash("0x6b17b938c6e4ef18b26ad81b9ca3515f27fd9c4e82aac56a1fd8eab288785e41"),
				Coinbase:         StringToAddress("0x5088d623ba0fcf0131e0897a91734a4d83596aa0"),
				StateRoot:        StringToHash("0x76ab0b899e8387436ff2658e2988f83cbf1af1590b9fe9feca3714f8d1824940"),
				TransactionsRoot: ZeroStorageHash,
				ReceiptsRoot:     ZeroStorageHash,
				Difficulty:       0x3fe802ffe,
				Number:           0x3,
				GasLimit:         0x1388,
				Timestamp:        0x55ba4260,
				ExtraData:        hexBytes(t, "0x476574682f76312e302e302d66633739643332642f6c696e75782f676f312e34"),
				MixDigest:        StringToHash("0x65e12eec23fe6555e6bcdb47aa25269ae106e5f16b54e1e92dcee25e1c8ad037"),
				Nonce:            0x2e9344e0cbde83ce,
			},
			uncles: []headerData{
				&HeaderLegacy{
					ParentHash:       StringToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
					UncleHash:        ZeroOmmerHash,
					Coinbase:         StringToAddress("0xc8ebccc5f5689fa8659d83713341e5ad19349448"),
					StateRoot:        StringToHash("0x1e6e030581fd1873b4784280859cd3b3c04aa85520f08c304cf5ee63d3935add"),
					TransactionsRoot: ZeroStorageHash,
					ReceiptsRoot:     ZeroStorageHash,
					Difficulty:       0x3ff800000,
					Number:           0x1,
					GasLimit:         0x1388,
					Timestamp:        0x55ba4242,
					ExtraData:        hexBytes(t, "0x59617465732052616e64616c6c202d2045746865724e696e6a61"),
					MixDigest:        StringToHash("0xf8c94dfe61cf26dcdf8cffeda337cf6a903d65c449d7691a022837f6e2d99459"),
					Nonce:            0x68b769c5451a7aea,
				},
			},
			uncleHashes: []Hash{StringToHash("0x5cd50096dbb856a6d1befa6de8f9c20decb299f375154427d90761dc0b101109")},
		},
		{
			// Mainnet block 17036342, Shanghai, no transactions, 16 withdrawals
			name: "17036342 withdrawals",
			hash: StringToHash("0x364bffc0465b3c31ce42370e3c580f7b154ede84e00de395eed56852b098f9e1"),
			size: 1124,
			header: &HeaderEIP4895{
				ParentHash:       StringToHash("0x8f57cfed18cf156ee51bbab84add8a88556655ee122345cda36d4e9d4c74330c"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x9695ee4778bdeb13b217979d93c4670cbf41cc65"),
				StateRoot:        StringToHash("0xc09ad0cc2734f5144aea3dc639062f4c45f0d76a79a94a8a4c1518cf1e1344e3"),
				TransactionsRoot: ZeroStorageHash,
				ReceiptsRoot:     ZeroStorageHash,
				Number:           0x103f436,
				GasLimit:         0x1c9c380,
				Timestamp:        0x6437811b,
				ExtraData:        hexBytes(t, "0xd883010b05846765746888676f312e32302e32856c696e7578"),
				MixDigest:        StringToHash("0x3a45817eb35f568e5e2be4d48bd204add99a26ee303d18ab826c5ad9fd353719"),
				BaseFeePerGas:    big.NewInt(0x7d80f8959),
				WithdrawalsRoot:  StringToHash("0x53f67b668ebcf852f8fab2e089eb143004666b4c4f170ab98289ca2bdddd9618"),
			},
			withdrawals: []Withdrawal{
				{Index: 0x5b9d, ValidatorIndex: 0x35b8d, Address: recipient, Amount: 0x920ec8e3},
				{Index: 0x5b9e, ValidatorIndex: 0x35b8e, Address: recipient, Amount: 0x9bb187e8},
				{Index: 0x5b9f, ValidatorIndex: 0x35b8f, Address: recipient, Amount: 0x8f7b768a},
				{Index: 0x5ba0, ValidatorIndex: 0x35b90, Address: recipient, Amount: 0x9174d557},
				{Index: 0x5ba1, ValidatorIndex: 0x35b91, Address: recipient, Amount: 0x9c9ee6a1},
				{Index: 0x5ba2, ValidatorIndex: 0x35b92, Address: recipient, Amount: 0x99aeb714},
				{Index: 0x5ba3, ValidatorIndex: 0x35b93, Address: recipient, Amount: 0x8f631b61},
				{Index: 0x5ba4, ValidatorIndex: 0x35b94, Address: recipient, Amount: 0x8f5770b8},
				{Index: 0x5ba5, ValidatorIndex: 0x35b95, Address: recipient, Amount: 0x95097234},
				{Index: 0x5ba6, ValidatorIndex: 0x35b96, Address: recipient, Amount: 0x893c0815},
				{Index: 0x5ba7, ValidatorIndex: 0x35b97, Address: recipient, Amount: 0xb43ba47f},
				{Index: 0x5ba8, ValidatorIndex: 0x35b98, Address: recipient, Amount: 0x9a4363f1},
				{Index: 0x5ba9, ValidatorIndex: 0x35b99, Address: recipient, Amount: 0x8e29b87a},
				{Index: 0x5baa, ValidatorIndex: 0x35b9a, Address: recipient, Amount: 0x92c90bfc},
				{Index: 0x5bab, ValidatorIndex: 0x35b9b, Address: recipient, Amount: 0x91871739},
				{Index: 0x5bac, ValidatorIndex: 0x35b9c, Address: recipient, Amount: 0x8ee46859},
			},
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			block := newTestBlock(t, testCase.header, testCase.txs, testCase.withdrawals)
			for _, uncle := range testCase.uncles {
				block.Uncles = append(block.Uncles, NewHeader(uncle))
			}

			got, err := block.ToRLP()
			require.NoError(t, err)
			assert.Len(t, got, testCase.size)
			assert.Equal(t, testCase.hash, block.Header.Hash())

			require.Len(t, block.Uncles, len(testCase.uncleHashes))

			for i, uncle := range block.Uncles {
				assert.Equal(t, testCase.uncleHashes[i], uncle.Hash())
			}
		})
	}
}

func TestBlockErrors(t *testing.T) {
	t.Parallel()

	shanghai := &HeaderEIP4895{BaseFeePerGas: big.NewInt(7)}
	london := &HeaderEIP1559{BaseFeePerGas: big.NewInt(7)}

	_, err := (&Block{}).ToRLP()
	require.ErrorIs(t, err, ErrNilBlockHeader)

	_, err = (&Block{}).ToProto()
	require.ErrorIs(t, err, ErrNilBlockHeader)

	_, err = (&Block{Header: NewHeader(london), Withdrawals: []Withdrawal{{Index: 1}}}).ToRLP()
	require.ErrorIs(t, err, ErrUnexpectedWithdrawals)

	// A Shanghai block always carries the withdrawals list, even when there are none
	got, err := (&Block{Header: NewHeader(shanghai)}).ToRLP()
	require.NoError(t, err)

	empty := []byte{0xc0}
	assert.Equal(t, ethrlp.EncodeArray([][]byte{shanghai.ToRLP(), empty, empty, empty}), got)

	require.ErrorIs(t, (&Block{}).FromProto(nil), ErrNilProtoBlock)
	require.ErrorIs(t, (&Withdrawal{}).FromProto(nil), ErrNilProtoWithdrawal)

	headerProto := shanghai.ToProto()

	err = (&Block{}).FromProto(&ethProto.Block{Header: headerProto, Withdrawals: []*ethProto.Withdrawal{nil}})
	require.ErrorIs(t, err, ErrNilProtoWithdrawal)

	err = (&Block{}).FromProto(&ethProto.Block{Header: headerProto, Uncles: []*ethProto.Header{nil}})
	require.ErrorIs(t, err, ErrNilProtoHeader)
}

func TestBlockProto(t *testing.T) {
	t.Parallel()

	uncle := NewHeader(&HeaderLegacy{Number: 2, Nonce: 0x42})
	block := &Block{
		Header: NewHeader(&HeaderEIP4895{Number: 3, BaseFeePerGas: big.NewInt(7)}),
		Uncles: []*Header{uncle},
		Withdrawals: []Withdrawal{
			{Address: StringToAddress("0x01"), Index: 1, ValidatorIndex: 2, Amount: 3},
			{Address: StringToAddress("0x02"), Index: 4, ValidatorIndex: 5, Amount: 6},
		},
	}

	want, err := block.ToRLP()
	require.NoError(t, err)

	got := protoRoundTrip(t, block)

	gotRLP, err := got.ToRLP()
	require.NoError(t, err)
	assert.Equal(t, want, gotRLP)

	require.Len(t, got.Uncles, 1)
	assert.Equal(t, uncle.Hash(), got.Uncles[0].Hash())
}
