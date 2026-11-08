package ethtypes

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/sig-0/ethtypes/keccak"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeRawTx decodes a raw transaction (EIP-2718).
// A legacy transaction starts with an RLP list prefix, a typed one with its type byte
func decodeRawTx(raw []byte) (*Transaction, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty transaction envelope")
	}

	var inner interface {
		transactionData
		FromRLP(data []byte) error
	}

	payload := raw[1:]

	switch {
	case raw[0] >= 0xc0:
		inner, payload = &TxLegacy{}, raw
	case raw[0] == Transaction2930:
		inner = &TxEIP2930{}
	case raw[0] == Transaction1559:
		inner = &TxEIP1559{}
	case raw[0] == Transaction4844:
		inner = &TxEIP4844{}
	case raw[0] == Transaction7702:
		inner = &TxEIP7702{}
	default:
		return nil, fmt.Errorf("unsupported transaction type 0x%x", raw[0])
	}

	if err := inner.FromRLP(payload); err != nil {
		return nil, err
	}

	return NewTransaction(inner), nil
}

// bigHex parses a hex string as a big integer
func bigHex(tb testing.TB, s string) *big.Int {
	tb.Helper()

	return new(big.Int).SetBytes(hexBytes(tb, s))
}

// assertDecodeRejects decodes valid into a T, then checks that FromRLP(bad)
// fails and leaves the decoded value unchanged
func assertDecodeRejects[T any, P interface {
	*T
	FromRLP(data []byte) error
}](t *testing.T, valid, bad []byte) {
	t.Helper()

	var tx T

	require.NoError(t, P(&tx).FromRLP(valid))

	before := tx

	assert.Error(t, P(&tx).FromRLP(bad))
	assert.Equal(t, before, tx)
}

func TestTxDecodersRejectMalformed(t *testing.T) {
	t.Parallel()

	testTable := []struct {
		rejects func(t *testing.T, valid, bad []byte)
		name    string
		raw     string
	}{
		{
			// Mainnet block 46147, tx 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060
			name:    "legacy",
			rejects: assertDecodeRejects[TxLegacy],
			raw:     "0xf86780862d79883d2000825208945df9b87991262f6ba471f09758cde1c0fc1de734827a69801ca088ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0a045e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a",
		},
		{
			// Mainnet block 17034954, tx 0x9c8b43f8b217d63b2e7ce1586a6b1daf6e1d251d7fcc0ef046320c95a0b11c31 (type byte removed)
			name:    "EIP-2930",
			rejects: assertDecodeRejects[TxEIP2930],
			raw:     "0xf871018301c6f28505a6bdbcfe8307a12094f82d8f922f0097f16cb5308fab224a380184b045872386f26fc1000080c001a0d2dc3dead6694d3838f7fbadd7424d203f81c391382ea02a9ed01c95d14421f2a03abb0cac1a6b8a310344365ebbffafcc09dd25cff3fe6fe7feb8970a3f55d2c9",
		},
		{
			// Mainnet block 17034954, tx 0xa775e81d9d7b0cbf56cb865b9221f85599098fa5486c935644e829778c1f024f (type byte removed)
			name:    "EIP-1559",
			rejects: assertDecodeRejects[TxEIP1559],
			raw:     "0xf874012785067925db9d85067925db9d825208941611011640513c50b8e1dd297506fd1738856b3a8803b223b02b9f53d280c001a0435cddc0ff6991cb71546bbbcf84d3391bc944b29ee118f33c568176dab96b1aa03f4ad2dba2bc1c636ac830a91a023fa2756a35bca4b16c82b5358a4dc9d3b2ba",
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			valid := hexBytes(t, testCase.raw)

			// The first field is one byte after the 2-byte list header,
			// so an empty list (0xc0) replaces it without changing any length
			fieldAsList := bytes.Clone(valid)
			fieldAsList[2] = 0xc0

			for _, bad := range [][]byte{
				nil,
				{},
				{0xc0},
				append(bytes.Clone(valid), 0x00),
				fieldAsList,
			} {
				testCase.rejects(t, valid, bad)
			}
		})
	}
}

func TestTransactionVectors(t *testing.T) {
	t.Parallel()

	const (
		// Sender of the ethereum/tests and EEST example transactions (private key 0x45a9...)
		senderA94f = "0xa94f5374Fce5edBC8E2a8697C15331677e6EbF0B"
		// Sender of the EEST frontier/examples and eip7702 transactions
		senderF6c3 = "0xF6C3A9EdC1aFA0aD5b720e4d42E1437C43D3B3fF"
	)

	testTable := []struct {
		name   string
		raw    string
		hash   string
		sender string
		txType byte
	}{
		{
			// Mainnet block 46147
			name:   "mainnet legacy, no EIP-155",
			raw:    "0xf86780862d79883d2000825208945df9b87991262f6ba471f09758cde1c0fc1de734827a69801ca088ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0a045e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a",
			hash:   "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060",
			sender: "0xA1E4380A3B1f749673E270229993eE55F35663b4",
			txType: TransactionLegacy,
		},
		{
			// Mainnet block 12965000
			name:   "mainnet legacy, EIP-155",
			raw:    "0xf867820cdc86016afba426008252089446499275b5c4d67dfa46b92d89aada3158ea392e808026a0cfaab0b753c1d71f695029e5b5da2f2f619370f5f224a42e1c19dcdcb9e814daa0606961e8b1dce9439df856ef1d1243f81f45938bac647568253260473efe7cc1",
			hash:   "0x2ecd08e86079f08cfc27c326aa01b1c8d62f288d5961118056bac7da315f94d9",
			sender: "0x46499275b5c4d67dfa46B92D89aADA3158ea392e",
			txType: TransactionLegacy,
		},
		{
			// Mainnet block 17034954
			name:   "mainnet type 1, empty access list",
			raw:    "0x01f871018301c6f28505a6bdbcfe8307a12094f82d8f922f0097f16cb5308fab224a380184b045872386f26fc1000080c001a0d2dc3dead6694d3838f7fbadd7424d203f81c391382ea02a9ed01c95d14421f2a03abb0cac1a6b8a310344365ebbffafcc09dd25cff3fe6fe7feb8970a3f55d2c9",
			hash:   "0x9c8b43f8b217d63b2e7ce1586a6b1daf6e1d251d7fcc0ef046320c95a0b11c31",
			sender: "0xc5a8859c44aC8AA2169aFaCF45B87C08593beC10",
			txType: Transaction2930,
		},
		{
			// Mainnet block 13500264
			name:   "mainnet type 1, 1 access-list entry",
			raw:    "0x01f901d201825dcb8523c3b8f7df8305a32394000000000000f0bc41c73af48f022f8c27b5350e80b90150002c000000d8d40abf7e456f20e95253e54490d8d30ea41574b24f741ee70201000000000000000000000124022c0d9f000000000000000000000000000000000000000000000000000000163d6c4d470000000000000000000000000000000000000000000000000000000000000000000000000000000000000000230000377650db9ca400d3fdff490000768521000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000007c88e6a0c2ddd26feeb64f039a2c41296fcb3f5640a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000014a5ed3e603a9eb2b00000000000000000000000000000000000000000000000001dfa18888ef5f7000000000d7d69420e95253e54490d8d30ea41574b24f741ee70201c080a09148491202dc360e30d294d4d7f058771167ad2076523581de33a1b3c2c65489a028a3f7ac01467999a59d2c61008e73623d85e8c6dd680efd2e0f511238a89adf",
			hash:   "0x36a2c13b12683d9d1b013fd85d04d84272d5ababba05ca508c71fbe61ea0fd5b",
			sender: "0x000000007Cb2bD00Ae5Eb839930Bb7847ae5B039",
			txType: Transaction2930,
		},
		{
			// Mainnet block 17034954
			name:   "mainnet type 2, empty access list",
			raw:    "0x02f874012785067925db9d85067925db9d825208941611011640513c50b8e1dd297506fd1738856b3a8803b223b02b9f53d280c001a0435cddc0ff6991cb71546bbbcf84d3391bc944b29ee118f33c568176dab96b1aa03f4ad2dba2bc1c636ac830a91a023fa2756a35bca4b16c82b5358a4dc9d3b2ba",
			hash:   "0xa775e81d9d7b0cbf56cb865b9221f85599098fa5486c935644e829778c1f024f",
			sender: "0x27979716c65B7C9b32732383be3c2984E6Cfc13B",
			txType: Transaction1559,
		},
		{
			// Mainnet block 16000036
			name:   "mainnet type 2, 1 access-list entry",
			raw:    "0x02f8af01826c72849502f9008505fa03367e82b98c94007933790a4f00000099e9001629d9fe7775b8008502b2801ebf845207a120f838f794c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2e1a05b1fd252f972f66f1de33cbc3b44509a4ec1fc4dee11857461b8b9131f605c4201a05289194989291140fced942d94199bcb92a3091ad22af124d67b498c0f47c35aa03255bccb0e7325f3996fbe7996e5a86a643086f22f0f4fc2e43a01880370d39c",
			hash:   "0x5cc0107499d668aab889c01a9c02b11964625c0aebb567e4d9e3bbb66b937146",
			sender: "0x3E92B6cd7f76b8f1B9821d55321433450272D7ad",
			txType: Transaction1559,
		},
		{
			// Mainnet block 19426589 (Cancun)
			name:   "mainnet type 3",
			raw:    "0x03f8930180843b9aca008601d1e4e4ea008252089400000000000000000000000000000000000000008080c0843b9aca00e1a00175f564b393e44640ecffddce4010a42c1c966413987d8a59a253ef64a0c5cf01a04169d4bf9df18182d86715d4ec031c20aded1a4a2613f57e0c0169e16cf763c2a006fc81d18602b8a1e065193488a7c943dfd780adb7b72dfc332de7d68605986e",
			hash:   "0x9c1fbda4f649ac806ab0faefbe94e1a60282eb374ead6aa01bac042f52b28a8c",
			sender: "0x40c35d4faf69234986cb599890c2d2ef546074a9",
			txType: Transaction4844,
		},
		{
			// Mainnet block 23068673 (Prague)
			name:   "mainnet type 4, Prague",
			raw:    "0x04f901f10182156382076284458e4b358307a120942228e5704b637131a3798a186caf18366c146f7480b9012474fa41210000000000000000000000000000000000000000000000000000000000000060dfcab42d3d5db4d3efa028649d22e140915add77e5eb872a3b82b638e3c011f067b4ea63d34e5b4ba81fcb8047829de9d0c08cb894cd86f631ade285732843860000000000000000000000000000000000000000000000000000000000000098a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000a030779804c096635c17126b7676a4b5fffbfb650000000000000000000000000000000000000000000000000000001a9b2cd7050000000000000000c0f85ef85c01947785a22facd31db653ba4928f1d5b81d093f0b2f822b4c01a084e9fe07a35306ad370de9682d1fdd90e48cc45aca583b0e0dc98a8046261114a00f0af16cf855c7eccc863cb8f15e6a391f45bac3becf0993662b7d97a405909280a0f0a4d3429f8ff097e7e7a5099101e39644c27ba9c105aaa376c69ce38f9194baa02e6e48cddc63476bc43e978474bcd195ee8d8b96c204f42e6cf0f9edf421051a",
			hash:   "0xb99d94de6d9d1d35b597901455e603ca5d2861f995f3492c6bb875299ab754ac",
			sender: "0xfc04fb6b93e0550f1607d5927d7a4ccac36c0457",
			txType: Transaction7702,
		},
		{
			// Mainnet block 26364325 (Osaka)
			name:   "mainnet type 4, Osaka",
			raw:    "0x04f8f301830295c38401ae67e9840443663983010f2c944de23f3f0fb3318287378adbde030cf61714b2f380a4c4d66de8000000000000000000000000333333320bb4a0345a7a102c49c72b37647aa088c0f85ff85d019484d05511614272694d3a9cebe896514dbde51f40830a2b4c01a0e4c73108b381a4ff6f94b90792466649e53278da479391958d055514e3f1b452a01fd74be7e6ed80c819c5942a245d2e09fc8a943fc718fe901915174569d0525680a04268b8d89e73a07e07e90a2e2ec9144192b2d462f7a38dc42f35e626227ce3e2a06dec9a66d710a721cdbd808866812b020cd36cc5c215f19f38fa0c892db7b41d",
			hash:   "0x7a5a82345b57a178c566008b0bd49fb240a31b9d253f7a4fe145861aab4d2054",
			sender: "0x333333320bb4a0345a7a102c49c72b37647aa088",
			txType: Transaction7702,
		},
		{
			// EIP-155, section "Example" (hash is keccak of the signed raw)
			name:   "EIP-155 example",
			raw:    "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
			hash:   "0x33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788",
			sender: "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
			txType: TransactionLegacy,
		},
		{
			// ethereum/tests v17.2 BlockchainTests/ValidBlocks/bcEIP4844-blobtransactions/blockWithAllTransactionTypes.json, blockWithAllTransactionTypes_Cancun
			name:   "spec block, legacy",
			raw:    "0xf864808203e885e8d4a5100094100000000000000000000000000000000000000a01801ca09de4adda6288582a6700dbcd8eb70c0a4a7fc9487d965f7bf22424e0bd121095a01cdb078764cc3770d5db847e99e10333aa7c356247baaf09b03eae04d64e7926",
			hash:   "0xa5df46a2eba63a4caa49f4b646a8c5ebcdaab603358a878c76385e140ec2b82a",
			sender: senderA94f,
			txType: TransactionLegacy,
		},
		{
			// ethereum/tests v17.2 BlockchainTests/ValidBlocks/bcEIP4844-blobtransactions/blockWithAllTransactionTypes.json, blockWithAllTransactionTypes_Cancun
			name:   "spec block, type 1",
			raw:    "0x01f86601018203e885e8d4a5100094100000000000000000000000000000000000000a0380c080a025090740da12684493e4fb466a3979e365b194e8cf462edf3c2c3be2f130bb2ea034fa18fb4c1bff4d957d72e28535d27f1352517a942aeaca0ed944085f0cd8bb",
			hash:   "0xb63d80d97305e1b508617d59177366e4ed72ca38ce0f8cc5de7c22baf800a3d3",
			sender: senderA94f,
			txType: Transaction2930,
		},
		{
			// ethereum/tests v17.2 BlockchainTests/ValidBlocks/bcEIP4844-blobtransactions/blockWithAllTransactionTypes.json, blockWithAllTransactionTypes_Cancun
			name:   "spec block, type 2",
			raw:    "0x02f8670102018203e885e8d4a5100094100000000000000000000000000000000000000a0580c080a0352a7be5002ce111bc5167f3addf97a75e2e0b810d826af71d2caae18aed284ea065d38f8a5c8948ce706842e8861fb21020b93a4d5e489162a0e6d419a457b735",
			hash:   "0x01f2da1c214988654e2595b804ab288f69a5198ec584cf5ba13e5b5416b8ec2e",
			sender: senderA94f,
			txType: Transaction1559,
		},
		{
			// ethereum/tests v17.2 BlockchainTests/ValidBlocks/bcEIP4844-blobtransactions/blockWithAllTransactionTypes.json, blockWithAllTransactionTypes_Cancun
			name:   "spec block, type 3",
			raw:    "0x03f8890103018203e885e8d4a5100094100000000000000000000000000000000000000a0780c00ae1a001a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8809f638144c46d5de7a9e630c0e7c5c63ae829ecfd8cc94715d9c29fe17c464de0a06c5fc54c3aa868ba35ef31a4e12431611631ab7bcdceb4214dd273d83f73b5e1",
			hash:   "0x859f215b2c6d4e57503d8c26e1485432568df6b3aff464cb7e272c163351efa0",
			sender: senderA94f,
			txType: Transaction4844,
		},
		{
			// EEST tests@v21.0.2 for_prague/prague/eip7702_set_code_tx/set_code_txs/valid_tx_invalid_auth_signature.json, test_valid_tx_invalid_auth_signature[fork_Prague-blockchain_test_from_state_test-r=0]
			name:   "spec block, type 4",
			raw:    "0x04f880018080078407270e00946280aceac5db12798d67870e2447ac01ab4e316a8080c0dbda019400000000000000000000000000000000000000008001800180a04763d5a7011dc615eb6682c7bdb9492bd48cddc3bc59e6a24653cfa031885d98a01cb2b4c89661dbd91f6653c13a55019f5f71061a408f6bd304697e68ee04aacc",
			hash:   "0x7fc57c54ae5bf285886b9c0fac148b1449151133647cb2c4151f7fe9e9ca13d6",
			sender: senderF6c3,
			txType: Transaction7702,
		},
		{
			// ethereum/tests v17.2 BlockchainTests/ValidBlocks/bcExample/shanghaiExample.json, shanghaiExample_Prague
			name:   "spec block, legacy contract creation",
			raw:    "0xf852802883061a808080866001600155001ba00b46eb2e2c914b99416e723a37be923605238a81c83c25b5f842544bebea8816a065730cb3fb806bd5260c1db09198459a2a2499e51b43a3780b48c1a3594133f2",
			hash:   "0x2139b05de62f9b1cbe3e8db073c5361fb6c9cfb5c0e021a492b0dc9d751c1303",
			sender: senderA94f,
			txType: TransactionLegacy,
		},
		{
			// EEST tests@v21.0.2 for_frontier/frontier/examples/block_intermediate_state/block_intermediate_state.json, test_block_intermediate_state[fork_Frontier-blockchain_test]
			name:   "spec block, Frontier",
			raw:    "0xf84d800a8407270e008080801ca0c541bc5e0babce3edb49cf49f57f51f546a50914d53177aaac4c4345efa9783ea0412cd87f12d177d860a906a989b8e6f677745b000c51e4163f04757c95ea2046",
			hash:   "0x07dd9f5acaf8a2996abb6c19f69b7fe36ad347d7199ad3ce3234c3af307d7fd0",
			sender: senderF6c3,
			txType: TransactionLegacy,
		},
		{
			// EEST tests@v21.0.2 for_osaka/frontier/examples/block_intermediate_state/block_intermediate_state.json, test_block_intermediate_state[fork_Osaka-blockchain_test]
			name:   "spec block, Osaka",
			raw:    "0xf84d800a84010000008080801ba0aeb2403cf9f2400e41c3093ff1f72f8b8555a114389364deb107638b1818e6cfa0320747229db6bba2e776c37a866f7a2052f841e30d795e62c945d9b4093c9fa7",
			hash:   "0xdd499bebe161e3dde406145a5cdb8db76b7ce190ead52c8b5f1a34a93592b8ca",
			sender: senderF6c3,
			txType: TransactionLegacy,
		},
		{
			// EEST tests@v21.0.2 for_prague/frontier/validation/transaction_rlp/valid_reencoded_transaction.json, test_valid_reencoded_transaction[]
			name:   "spec valid_reencoded_transaction",
			raw:    "0xf85f800a82753094c0f6dc9e5836f54caadbf59cc69346c508e1992b018026a05620163c1c60b8e79c827610d50d89a9dbff17febe1e604c539f902de467f68da010bb198840c4c29c297d4b36b0c6d057cfa5df4d5b01ef8ab4e3ae12c1ccde59",
			hash:   "0x5be02ea9c507ca3d18ad9175fa92462ea91f8e015b36626a73be3477854be6bd",
			sender: senderF6c3,
			txType: TransactionLegacy,
		},
		{
			// ethereum/tests v17.2 TransactionTests/ttEIP2930/accessListStorage32Bytes.json, accessListStorage32Bytes
			name:   "spec accessListStorage32Bytes",
			raw:    "0x01f89a018001826a4094095e7baea6a6c7c4c2dfeb977efac326af552d878080f838f794a95e7baea6a6c7c4c2dfeb977efac326af552d87e1a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36",
			hash:   "0xb4f8b14a7aaf85ec2f76be9fbe4155deae1f87b2da95af73be3c27ed8d4c8cb7",
			sender: "0xebe76799923fd62804659fb00b4f0f1a94c0eb1e",
			txType: Transaction2930,
		},
		{
			// ethereum/tests v17.2 TransactionTests/ttEIP1559/GasLimitPriceProductOverflowtMinusOne.json, GasLimitPriceProductOverflowtMinusOne
			name:   "spec GasLimitPriceProductOverflowtMinusOne",
			raw:    "0x02f885018084773594009f02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82520894095e7baea6a6c7c4c2dfeb977efac326af552d878080c080a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36",
			hash:   "0xdad8bff3ecfcf95169b1d5625b47f3372be795802bc4fe570991cf332f609334",
			sender: "0xae2aec498d20869d441eaaf708fb1e375ae1787d",
			txType: Transaction1559,
		},
		{
			// ethereum/tests v17.2 TransactionTests/ttEIP3860/DataTestEnoughGasInitCode.json, DataTestEnoughGasInitCode
			name:   "spec DataTestEnoughGasInitCode",
			raw:    "0xf88c800a82d00c8080b840000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a01fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804",
			hash:   "0x8968e3a4186bf5edf31a2506b42d0ae47478fe5f44fb591b121ac08ec173f816",
			sender: "0xce520dd42b637d431c53409a24801eb14ae8e423",
			txType: TransactionLegacy,
		},
		{
			// ethereum/tests v17.2 TransactionTests/ttVValue/V_equals37.json, V_equals37
			name:   "spec V_equals37",
			raw:    "0xf865808698852840a46f82d6d894095e7baea6a6c7c4c2dfeb977efac326af552d87808025a098ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa01887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3",
			hash:   "0x4782cb5edcaeda1f0aef204b161214f124cefade9e146245183abbb9ca01bca5",
			sender: "0x2ea991808ba979ba103147edfd72304ebd95c028",
			txType: TransactionLegacy,
		},
		{
			// ethereum/tests v17.2 TransactionTests/ttNonce/TransactionWithHighNonce64Minus2.json, TransactionWithHighNonce64Minus2
			name:   "spec TransactionWithHighNonce64Minus2",
			raw:    "0xf86788fffffffffffffffe0182520894095e7baea6a6c7c4c2dfeb977efac326af552d8780801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a01fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804",
			hash:   "0xf1c8d1fb7df452d50d11d4c94a4ebeecd62f3669c980fbe37c2b65895de2fa7c",
			sender: "0x254f592c3cf7cffd797c7e1322effa8a2671b6bb",
			txType: TransactionLegacy,
		},
		{
			// ethereum/tests v17.2 TransactionTests/ttNonce/TransactionWithEmptyBigInt.json, TransactionWithEmptyBigInt
			name:   "spec TransactionWithEmptyBigInt",
			raw:    "0xf85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870b801ca048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a010002cef538bc0c8e21c46080634a93f4d752bc9fe4b546b60ac055e842d342b",
			hash:   "0xc857564511d0d8d17d9a6a8ebe9104a50f450264118755327907cb31ff8096ad",
			sender: "0xc00ed9ae069f0c2c89d4065a52b467a719269bc1",
			txType: TransactionLegacy,
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var (
				raw    = hexBytes(t, testCase.raw)
				hash   = StringToHash(testCase.hash)
				sender = StringToAddress(testCase.sender)
			)

			tx, err := decodeRawTx(raw)
			require.NoError(t, err)

			assert.Equal(t, testCase.txType, tx.Type())

			signed, err := tx.ToSignedRLP()
			require.NoError(t, err)
			assert.Equal(t, raw, signed)

			txHash, err := tx.TxHash()
			require.NoError(t, err)
			assert.Equal(t, hash, txHash)

			from, err := tx.From()
			require.NoError(t, err)
			assert.Equal(t, sender, from)

			unsigned, err := tx.ToRLP()
			require.NoError(t, err)
			assert.Equal(t, BytesToHash(keccak.New().Hash(unsigned)), tx.Hash())

			pb, err := tx.ToProto()
			require.NoError(t, err)
			assert.Equal(t, hash.ToBytes(), pb.Hash)

			decoded := &Transaction{}
			require.NoError(t, decoded.FromProto(pb))

			decodedSigned, err := decoded.ToSignedRLP()
			require.NoError(t, err)
			assert.Equal(t, raw, decodedSigned)

			decodedFrom, err := decoded.From()
			require.NoError(t, err)
			assert.Equal(t, sender, decodedFrom)
		})
	}
}

func TestTransactionEncoders(t *testing.T) {
	t.Parallel()

	decimal := func(s string) *big.Int {
		x, ok := new(big.Int).SetString(s, 10)
		require.True(t, ok)

		return x
	}

	address := func(s string) *Address {
		a := StringToAddress(s)

		return &a
	}

	// A matching TxHash also checks the signed RLP encoding
	testTable := []struct {
		tx          transactionData
		name        string
		hash        string
		sender      string
		signingData string
	}{
		{
			// EIP-155, section "Example"
			name: "legacy, EIP-155 example",
			tx: &TxLegacy{
				GasPrice: big.NewInt(20_000_000_000),
				Value:    decimal("1000000000000000000"),
				V:        big.NewInt(37),
				R:        decimal("18515461264373351373200002665853028612451056578545711640558177340181847433846"),
				S:        decimal("46948507304638947509940763649030358759909902576025900602547168820602576006531"),
				To:       address("0x3535353535353535353535353535353535353535"),
				Nonce:    9,
				Gas:      21000,
			},
			hash:        "0x33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788",
			sender:      "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
			signingData: "0xec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080",
		},
		{
			// Mainnet block 17034954, tx 0x9c8b43f8b217d63b2e7ce1586a6b1daf6e1d251d7fcc0ef046320c95a0b11c31
			name: "type 1, empty access list",
			tx: &TxEIP2930{
				ChainID:  big.NewInt(1),
				GasPrice: big.NewInt(0x05a6bdbcfe),
				Value:    big.NewInt(0x2386f26fc10000),
				YParity:  big.NewInt(1),
				R:        bigHex(t, "0xd2dc3dead6694d3838f7fbadd7424d203f81c391382ea02a9ed01c95d14421f2"),
				S:        bigHex(t, "0x3abb0cac1a6b8a310344365ebbffafcc09dd25cff3fe6fe7feb8970a3f55d2c9"),
				To:       address("0xf82d8f922f0097f16cb5308fab224a380184b045"),
				Nonce:    0x1c6f2,
				Gas:      0x07a120,
			},
			hash:   "0x9c8b43f8b217d63b2e7ce1586a6b1daf6e1d251d7fcc0ef046320c95a0b11c31",
			sender: "0xc5a8859c44aC8AA2169aFaCF45B87C08593beC10",
		},
		{
			// Mainnet block 16000036, tx 0x5cc0107499d668aab889c01a9c02b11964625c0aebb567e4d9e3bbb66b937146
			name: "type 2, 1 access-list entry",
			tx: &TxEIP1559{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(0x9502f900),
				MaxFeePerGas:         big.NewInt(0x05fa03367e),
				Value:                big.NewInt(0x02b2801ebf),
				YParity:              big.NewInt(1),
				R:                    bigHex(t, "0x5289194989291140fced942d94199bcb92a3091ad22af124d67b498c0f47c35a"),
				S:                    bigHex(t, "0x3255bccb0e7325f3996fbe7996e5a86a643086f22f0f4fc2e43a01880370d39c"),
				To:                   address("0x007933790a4f00000099e9001629d9fe7775b800"),
				Data:                 hexBytes(t, "0x5207a120"),
				AccessList: AccessList{
					{
						Address:     StringToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
						StorageKeys: []Hash{StringToHash("0x5b1fd252f972f66f1de33cbc3b44509a4ec1fc4dee11857461b8b9131f605c42")},
					},
				},
				Nonce: 0x6c72,
				Gas:   0xb98c,
			},
			hash:   "0x5cc0107499d668aab889c01a9c02b11964625c0aebb567e4d9e3bbb66b937146",
			sender: "0x3E92B6cd7f76b8f1B9821d55321433450272D7ad",
		},
		{
			// Mainnet block 19426589, tx 0x9c1fbda4f649ac806ab0faefbe94e1a60282eb374ead6aa01bac042f52b28a8c
			name: "type 3",
			tx: &TxEIP4844{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(0x3b9aca00),
				MaxFeePerGas:         big.NewInt(0x01d1e4e4ea00),
				MaxFeePerBlobGas:     big.NewInt(0x3b9aca00),
				Value:                big.NewInt(0),
				YParity:              big.NewInt(1),
				R:                    bigHex(t, "0x4169d4bf9df18182d86715d4ec031c20aded1a4a2613f57e0c0169e16cf763c2"),
				S:                    bigHex(t, "0x06fc81d18602b8a1e065193488a7c943dfd780adb7b72dfc332de7d68605986e"),
				BlobVersionedHashes:  []Hash{StringToHash("0x0175f564b393e44640ecffddce4010a42c1c966413987d8a59a253ef64a0c5cf")},
				Gas:                  0x5208,
			},
			hash:   "0x9c1fbda4f649ac806ab0faefbe94e1a60282eb374ead6aa01bac042f52b28a8c",
			sender: "0x40c35d4faf69234986cb599890c2d2ef546074a9",
		},
		{
			// Mainnet block 23068673, tx 0xb99d94de6d9d1d35b597901455e603ca5d2861f995f3492c6bb875299ab754ac
			name: "type 4",
			tx: &TxEIP7702{
				ChainID:              big.NewInt(1),
				MaxPriorityFeePerGas: big.NewInt(0x762),
				MaxFeePerGas:         big.NewInt(0x458e4b35),
				Value:                big.NewInt(0),
				YParity:              big.NewInt(0),
				R:                    bigHex(t, "0xf0a4d3429f8ff097e7e7a5099101e39644c27ba9c105aaa376c69ce38f9194ba"),
				S:                    bigHex(t, "0x2e6e48cddc63476bc43e978474bcd195ee8d8b96c204f42e6cf0f9edf421051a"),
				Data:                 hexBytes(t, "0x74fa41210000000000000000000000000000000000000000000000000000000000000060dfcab42d3d5db4d3efa028649d22e140915add77e5eb872a3b82b638e3c011f067b4ea63d34e5b4ba81fcb8047829de9d0c08cb894cd86f631ade285732843860000000000000000000000000000000000000000000000000000000000000098a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000a030779804c096635c17126b7676a4b5fffbfb650000000000000000000000000000000000000000000000000000001a9b2cd7050000000000000000"),
				AuthorizationList: AuthorizationList{
					{
						ChainID: big.NewInt(1),
						YParity: big.NewInt(1),
						R:       bigHex(t, "0x84e9fe07a35306ad370de9682d1fdd90e48cc45aca583b0e0dc98a8046261114"),
						S:       bigHex(t, "0x0f0af16cf855c7eccc863cb8f15e6a391f45bac3becf0993662b7d97a4059092"),
						Address: StringToAddress("0x7785a22facd31db653ba4928f1d5b81d093f0b2f"),
						Nonce:   0x2b4c,
					},
				},
				To:    StringToAddress("0x2228e5704b637131a3798a186caf18366c146f74"),
				Nonce: 0x1563,
				Gas:   0x7a120,
			},
			hash:   "0xb99d94de6d9d1d35b597901455e603ca5d2861f995f3492c6bb875299ab754ac",
			sender: "0xfc04fb6b93e0550f1607d5927d7a4ccac36c0457",
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			tx := NewTransaction(testCase.tx)

			txHash, err := tx.TxHash()
			require.NoError(t, err)
			assert.Equal(t, StringToHash(testCase.hash), txHash)

			from, err := tx.From()
			require.NoError(t, err)
			assert.Equal(t, StringToAddress(testCase.sender), from)

			if testCase.signingData != "" {
				unsigned, err := tx.ToRLP()
				require.NoError(t, err)
				assert.Equal(t, hexBytes(t, testCase.signingData), unsigned)
			}
		})
	}
}

func TestTransactionSpecInvalid(t *testing.T) {
	t.Parallel()

	// Every row has an invalid RLP structure, non-canonical RLP or an invalid field width
	testTable := []struct {
		name string
		raw  string
	}{
		// EEST tests@v21.0.2 fixtures/transaction_tests/for_prague/frontier/validation/...
		{name: "tx_nonce_overflow", raw: "0xf868890100000000000000000a82520894c0f6dc9e5836f54caadbf59cc69346c508e1992b80801ca037f68b9ea67aa96dcef806e691314bec49d0d6a7b0da43347fd8907a466944eda059b95678162573fc440c25b1c11339b7700153cdc2fe029760c7e5581122282e"},
		{name: "data_size_leading_zeros", raw: "0xf8a1800a8275309495d1be958d22adf294428c13cc71d89ff320bfd301b90040ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff25a0e423a0d3c21e216f22247fd87e9b933f3197b02f0285f461a8ec0ff6f3d212e7a02ece800533fdb4775b659ba4df6fc93f0f920159fe5b903470ad96221f6516f3"},
		{name: "field_as_list[field_nonce]", raw: "0xf860c1800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764"},
		{name: "field_leading_zeros[field_nonce]", raw: "0xf85f000a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764"},
		{name: "field_leading_zeros[field_r]", raw: "0xf860800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a100b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764"},
		{name: "field_overflow[field_r]", raw: "0xf860800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a1010000000000000000000000000000000000000000000000000000000000000000a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764"},
		{name: "invalid_envelope[empty]", raw: "0x"},
		{name: "invalid_envelope[reserved_type_byte]", raw: "0xfff85f800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764"},
		{name: "invalid_structure[mutation_extra_byte]", raw: "0xf85f800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf6776400"},
		{name: "invalid_structure[mutation_header_declares_less]", raw: "0xf85e800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764"},
		{name: "invalid_structure[mutation_too_few_elements]", raw: "0xf83e800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659"},
		{name: "invalid_structure[mutation_too_many_elements]", raw: "0xf860800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf6776480"},
		{name: "invalid_structure[mutation_truncated]", raw: "0xf85f800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf677"},
		{name: "invalid_structure[mutation_tx_as_byte_string]", raw: "0xb85f800a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764"},
		{name: "non_canonical_single_byte", raw: "0xf86081010a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018025a080878ed5d3ec3bb19f5e8a64927a2a2d7157564215000539dd8ad76d492b8811a05c5eb09a7cc864c57d445013c3d1de953d17dab3090a4b10ebbfc1442bfd4a5c"},
		{name: "to_address_size[size_19]", raw: "0xf85e800a8275309395d1be958d22adf294428c13cc71d89ff320bf018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764"},
		{name: "to_address_size[size_21]", raw: "0xf860800a827530950095d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764"},
		// EEST tests@v21.0.2 fixtures/transaction_tests/for_prague/prague/eip7702_set_code_tx/invalid_tx/...
		{name: "invalid_tx_invalid_address[non_zero_address-oversized]", raw: "0x04f8c201808007830186a09400000000000000000000000000000000000000008080c0f85df85b80950000000000000000000000000000000000000000018080a056993a2bdc389116854e72d75751bd65905c1f6c4a48427d8ce12795a2e4ad93a049621c190d70bc05bc23d31a9c64fe188ee34e39fdd5846508af6ab6500fb98201a067d9ceb81449335e8d302d0b4d47739df691186d62d4b514a6fc39b0a6c89ac9a01e012a83c5addbb82a0d1662a5d9bb0b33953edd1dcf878144369b5d7e19e196"},
		{name: "invalid_tx_invalid_auth_chain_id[non_zero_address-auth_chain_id=2**256]", raw: "0x04f8e201808007830186a09400000000000000000000000000000000000000008080c0f87df87ba10100000000000000000000000000000000000000000000000000000000000000009400000000000000000000000000000000000000018001a087957a5e76c0843bba6aa29182d022ee14ad54781079fbe91ad83634288e3800a06cd9e294d174c8b70daf565dce93946a8192c3a5a6f1f65bf65a9f6bcb0d1e8580a0c87fcbc33d82b423348fc768458be44a9df8b81d07e73d3e7a7eaf6c79a63784a0192bbd1a927f0cb853814ae830e3fd01914b8d89c007e3d545458a7918dda17e"},
		{name: "invalid_tx_invalid_authorization_tuple_encoded_as_bytes[non_zero_address]", raw: "0x04f8c301808007830186a09400000000000000000000000000000000000000008080c0f85eb85cf85a809400000000000000000000000000000000000000018001a0bd85b1e84a4bb5d161e65c31b216c77d686ac97deebbbd79a8ee780a79693759a019f911b87741efb3140f3b107036d44724d392b779fe9e56ae8c903580e2560e01a08b0d9a6cb585a775401d81a7083647dae7a5ee00fdf8d628647ba4cefabae3dda079965a1700ea5993a3cb769ec1a23a3ae69b2eec1c13ff49e2159ccc6c21cf63"},
		{name: "invalid_tx_invalid_authorization_tuple_extra_element[non_zero_address-extra_element_value_0]", raw: "0x04f8c201808007830186a09400000000000000000000000000000000000000008080c0f85df85b809400000000000000000000000000000000000000018001a0bd85b1e84a4bb5d161e65c31b216c77d686ac97deebbbd79a8ee780a79693759a019f911b87741efb3140f3b107036d44724d392b779fe9e56ae8c903580e2560e8080a0ebe75927338318bba40a4760868b69bf5c22b7eab6e7d4a9abae0887282d3993a03e3933d9b60a98c152c384b0179cc1caa8431ba1ead8c57bbadfef44fe4238e4"},
		{name: "invalid_tx_invalid_authorization_tuple_missing_element[non_zero_address-missing_address]", raw: "0x04f8ac01808007830186a09400000000000000000000000000000000000000008080c0f847f845808001a0bd85b1e84a4bb5d161e65c31b216c77d686ac97deebbbd79a8ee780a79693759a019f911b87741efb3140f3b107036d44724d392b779fe9e56ae8c903580e2560e01a00c9b5ea4c645cfedcde52e2e5e45cf6fff010b33f87fdca3df6de7f756c04c42a01a61241ea46fcf15e19866e011419f3e7efdac63dc926ae448c0f7830e752802"},
		{name: "invalid_tx_invalid_nonce[non_zero_address-nonce=2**256]", raw: "0x04f8e201808007830186a09400000000000000000000000000000000000000008080c0f87df87b80940000000000000000000000000000000000000001a101000000000000000000000000000000000000000000000000000000000000000080a085fbc2a4fe5f8925cf03c758c73e8729a4252e1b6856d14605d5fad273167933a04ba2bf75567d217ce732bd11b2b5cb44ab565aa240b728337b6ce60ca2e99aae80a0dd9ff1c31b4ae35e0e375ffdd88ff2ef6b63f26fd90e34798414ec76195b91a0a003c63e360cbe4812b9fc3844f9b6fe4da6cc575303a3ff013535442d5bd6ef5f"},
		{name: "invalid_tx_invalid_nonce_as_list[non_zero_address-nonce=empty-list]", raw: "0x04f8c101808007830186a09400000000000000000000000000000000000000008080c0f85cf85a80940000000000000000000000000000000000000001c001a0851d76341164c376c669eb7371a75422427ca4b09e1db16749b145f2f30df5eea0398373dc3fcd0a7a57dfea9167e32bd3365a0ffdb1bd8f8b8015cec7360a1ae480a09aaf469252d160948e27bdbe6fde8d1712fb8140181ae7aabd891304138effd6a074ddd834d9930bf593919f0ba8f8c3b60eab2389b0f7675c1f82ce0f91a3e0e0"},
		{name: "invalid_tx_invalid_nonce_encoding[non_zero_address]", raw: "0x04f8c301808007830186a09400000000000000000000000000000000000000008080c0f85ef85c8094000000000000000000000000000000000000000182000001a0102f8433dce557de25f5459c65c55c37f04e38e8a3e1452ba7acdaac39aa3663a0772dc99ee2144c63fd630717676ae7828fcc5ab8604a62e7856bc48ce59d1ff680a09e6ce2dc936e7d6d98d954608301d5c640a4928a09848076f77f36ee1b6f9f4fa060e7220a371a1f530eeb7735e64c1b620939dfc2b835f05d9cb312682197d46f"},
		// ethereum/tests v17.2 (commit c67e485ff8b5be9abc8ad15345ec21aa22e290d9) TransactionTests/...
		{name: "ttEIP2930/accessListAddressGreaterThan20", raw: "0x01f8be018001826a4094095e7baea6a6c7c4c2dfeb977efac326af552d878080f85cf85a95b94f5374fce5edbc8e2a8697c15331677e6ebf0b1cf842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000180a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36"},
		{name: "ttEIP2930/accessListAddressLessThan20", raw: "0x01f8bc018001826a4094095e7baea6a6c7c4c2dfeb977efac326af552d878080f85af858939e7baea6a6c7c4c2dfeb977efac326af552d87f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000180a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36"},
		{name: "ttEIP2930/accessListStorageOver32Bytes", raw: "0x01f89c018001826a4094095e7baea6a6c7c4c2dfeb977efac326af552d878080f83af83894a95e7baea6a6c7c4c2dfeb977efac326af552d87e2a101000000000000000000000000000000000000000000000000000000000000000080a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36"},
		{name: "ttWrongRLP/aMaliciousRLP", raw: "0xb8"},
		{name: "ttWrongRLP/RLPElementIsListWhenItShouldntBe", raw: "0xf8698001cc83646f6783676f648363617494095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804"},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := decodeRawTx(hexBytes(t, testCase.raw))
			assert.Error(t, err)
		})
	}

	t.Run("empty_authorization_list decodes (validity rule)", func(t *testing.T) {
		t.Parallel()

		// EEST tests@v21.0.2 for_prague/prague/eip7702_set_code_tx/invalid_tx/empty_authorization_list.json, test_empty_authorization_list[]
		raw := hexBytes(t, "0x04f86401808007830186a09400000000000000000000000000000000000000008080c0c001a0884bf485199d5e86e675e79f17a710b754a36915a33a2838c24e1e53378699f1a074085ca12ad0f729b6bd6c37a7a23e925c7e1e87a557ad3100a9113786c98afd")

		tx, err := decodeRawTx(raw)
		require.NoError(t, err)

		signed, err := tx.ToSignedRLP()
		require.NoError(t, err)
		assert.Equal(t, raw, signed)
	})
}

func TestTransactionProto(t *testing.T) {
	t.Parallel()

	t.Run("FromProto into a used transaction resets the sender and hash", func(t *testing.T) {
		t.Parallel()

		// Mainnet block 12965000
		used, err := decodeRawTx(hexBytes(t, "0xf867820cdc86016afba426008252089446499275b5c4d67dfa46b92d89aada3158ea392e808026a0cfaab0b753c1d71f695029e5b5da2f2f619370f5f224a42e1c19dcdcb9e814daa0606961e8b1dce9439df856ef1d1243f81f45938bac647568253260473efe7cc1"))
		require.NoError(t, err)

		// Mainnet block 16000036
		other, err := decodeRawTx(hexBytes(t, "0x02f8af01826c72849502f9008505fa03367e82b98c94007933790a4f00000099e9001629d9fe7775b8008502b2801ebf845207a120f838f794c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2e1a05b1fd252f972f66f1de33cbc3b44509a4ec1fc4dee11857461b8b9131f605c4201a05289194989291140fced942d94199bcb92a3091ad22af124d67b498c0f47c35aa03255bccb0e7325f3996fbe7996e5a86a643086f22f0f4fc2e43a01880370d39c"))
		require.NoError(t, err)

		// Cache the sender and hash of the used transaction
		usedFrom, err := used.From()
		require.NoError(t, err)

		usedHash := used.Hash()

		pb, err := other.ToProto()
		require.NoError(t, err)
		require.NoError(t, used.FromProto(pb))

		from, err := used.From()
		require.NoError(t, err)
		assert.Equal(t, StringToAddress("0x3E92B6cd7f76b8f1B9821d55321433450272D7ad"), from)
		assert.NotEqual(t, usedFrom, from)

		assert.Equal(t, other.Hash(), used.Hash())
		assert.NotEqual(t, usedHash, used.Hash())

		txHash, err := used.TxHash()
		require.NoError(t, err)
		assert.Equal(t, StringToHash("0x5cc0107499d668aab889c01a9c02b11964625c0aebb567e4d9e3bbb66b937146"), txHash)
	})

	t.Run("nil and empty payloads", func(t *testing.T) {
		t.Parallel()

		assert.ErrorIs(t, (&Transaction{}).FromProto(nil), ErrNilProtoTx)
		assert.Error(t, (&Transaction{}).FromProto(&txProto.Transaction{}))
	})

	t.Run("ToProto keeps To (EIP-1559, EIP-2930)", func(t *testing.T) {
		t.Parallel()

		to := StringToAddress("0x3535353535353535353535353535353535353535")

		tx1559 := &TxEIP1559{To: &to}
		assert.Equal(t, to.ToBytes(), tx1559.ToProto().To)
		require.NotNil(t, tx1559.To)
		assert.Equal(t, to, *tx1559.To)

		tx2930 := &TxEIP2930{To: &to}
		assert.Equal(t, to.ToBytes(), tx2930.ToProto().To)
		require.NotNil(t, tx2930.To)
		assert.Equal(t, to, *tx2930.To)
	})

	t.Run("FromProto rejects another payload type", func(t *testing.T) {
		t.Parallel()

		var (
			legacy  = &txProto.Transaction{Payload: &txProto.Transaction_Legacy{Legacy: &txProto.Legacy{}}}
			eip2930 = &txProto.Transaction{Payload: &txProto.Transaction_Eip2930{Eip2930: &txProto.EIP2930{}}}
		)

		assert.ErrorIs(t, (&TxLegacy{}).FromProto(eip2930), ErrInvalidProtoLegacyTx)
		assert.ErrorIs(t, (&TxEIP2930{}).FromProto(legacy), ErrInvalidProtoEIP2930Tx)
		assert.ErrorIs(t, (&TxEIP1559{}).FromProto(legacy), ErrInvalidProtoEIP1559Tx)
		assert.ErrorIs(t, (&TxEIP4844{}).FromProto(legacy), ErrInvalidProtoEIP4844Tx)
		assert.ErrorIs(t, (&TxEIP7702{}).FromProto(legacy), ErrInvalidProtoEIP7702Tx)
	})

	t.Run("nil access-list entry gives the zero entry", func(t *testing.T) {
		t.Parallel()

		var (
			nilEntry = []*txProto.AccessListEntry{nil}
			to       = ZeroAddress.ToBytes() // types 3 and 4 need a 20-byte 'to'
		)

		for _, pb := range []*txProto.Transaction{
			{Payload: &txProto.Transaction_Eip2930{Eip2930: &txProto.EIP2930{AccessList: nilEntry}}},
			{Payload: &txProto.Transaction_Eip1559{Eip1559: &txProto.EIP1559{AccessList: nilEntry}}},
			{To: to, Payload: &txProto.Transaction_Eip4844{Eip4844: &txProto.EIP4844{AccessList: nilEntry}}},
			{To: to, Payload: &txProto.Transaction_Eip7702{Eip7702: &txProto.EIP7702{AccessList: nilEntry}}},
		} {
			tx := &Transaction{}
			require.NoError(t, tx.FromProto(pb))

			require.Len(t, tx.AccessList(), 1)
			assert.Equal(t, ZeroAddress, tx.AccessList()[0].Address)
			assert.Empty(t, tx.AccessList()[0].StorageKeys)
		}
	})

	t.Run("nil authorization is an error and leaves the receiver unchanged", func(t *testing.T) {
		t.Parallel()

		pb := &txProto.Transaction{To: ZeroAddress.ToBytes(), Payload: &txProto.Transaction_Eip7702{Eip7702: &txProto.EIP7702{
			AuthorizationList: []*txProto.Authorization{nil},
		}}}

		tx := &TxEIP7702{Nonce: 7, ChainID: big.NewInt(1)}
		before := tx.ToSignedRLP()

		require.ErrorIs(t, tx.FromProto(pb), ErrInvalidProtoEIP7702Tx)
		assert.Equal(t, before, tx.ToSignedRLP())
		assert.Error(t, (&Transaction{}).FromProto(pb))
	})

	t.Run("types 3 and 4 reject wrong-length to, address and blob hash", func(t *testing.T) {
		t.Parallel()

		var (
			to      = make([]byte, 20)
			address = make([]byte, 20)
			hash    = make([]byte, 32)
		)

		eip4844 := func(to []byte, hashes ...[]byte) *txProto.Transaction {
			return &txProto.Transaction{To: to, Payload: &txProto.Transaction_Eip4844{Eip4844: &txProto.EIP4844{
				BlobVersionedHashes: hashes,
			}}}
		}

		eip7702 := func(to, address []byte) *txProto.Transaction {
			return &txProto.Transaction{To: to, Payload: &txProto.Transaction_Eip7702{Eip7702: &txProto.EIP7702{
				AuthorizationList: []*txProto.Authorization{{Address: address}},
			}}}
		}

		testTable := []struct {
			fromProto func(pb *txProto.Transaction) error
			valid     *txProto.Transaction
			bad       *txProto.Transaction
			sentinel  error
			name      string
		}{
			{
				name:      "type 3, empty to",
				fromProto: (&TxEIP4844{}).FromProto,
				valid:     eip4844(to, hash),
				bad:       eip4844(nil, hash),
				sentinel:  ErrInvalidProtoEIP4844Tx,
			},
			{
				name:      "type 3, 32-byte to",
				fromProto: (&TxEIP4844{}).FromProto,
				valid:     eip4844(to, hash),
				bad:       eip4844(hash, hash),
				sentinel:  ErrInvalidProtoEIP4844Tx,
			},
			{
				name:      "type 3, 31-byte blob hash",
				fromProto: (&TxEIP4844{}).FromProto,
				valid:     eip4844(to, hash),
				bad:       eip4844(to, hash, hash[:31]),
				sentinel:  ErrInvalidProtoEIP4844Tx,
			},
			{
				name:      "type 4, empty to",
				fromProto: (&TxEIP7702{}).FromProto,
				valid:     eip7702(to, address),
				bad:       eip7702(nil, address),
				sentinel:  ErrInvalidProtoEIP7702Tx,
			},
			{
				name:      "type 4, 19-byte to",
				fromProto: (&TxEIP7702{}).FromProto,
				valid:     eip7702(to, address),
				bad:       eip7702(to[:19], address),
				sentinel:  ErrInvalidProtoEIP7702Tx,
			},
			{
				name:      "type 4, 21-byte authorization address",
				fromProto: (&TxEIP7702{}).FromProto,
				valid:     eip7702(to, address),
				bad:       eip7702(to, make([]byte, 21)),
				sentinel:  ErrInvalidProtoEIP7702Tx,
			},
		}

		for _, testCase := range testTable {
			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				require.NoError(t, (&Transaction{}).FromProto(testCase.valid))

				assert.ErrorIs(t, testCase.fromProto(testCase.bad), testCase.sentinel)
				assert.Error(t, (&Transaction{}).FromProto(testCase.bad))
			})
		}
	})
}

// assertSignedRoundTrip checks that a FromRLP decoder never panics,
// and that ToSignedRLP returns the accepted payload (with the type prefix)
func assertSignedRoundTrip(t *testing.T, tx interface {
	FromRLP(data []byte) error
	ToSignedRLP() []byte
}, typePrefix, payload []byte,
) {
	t.Helper()

	if tx.FromRLP(payload) != nil {
		return
	}

	assert.Equal(t, slices.Concat(typePrefix, payload), tx.ToSignedRLP())
}

func FuzzTxLegacyFromRLP(f *testing.F) {
	for _, seed := range []string{
		// EIP-155, section "Example"
		"0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
		// EEST tests@v21.0.2 field_leading_zeros.json, test_field_leading_zeros[field_nonce
		"0xf85f000a8275309495d1be958d22adf294428c13cc71d89ff320bfd3018026a0b08e73e275d6dc04d76348f5a7c00ac633b73677e2a3b105eab67d02aa719659a0093c70cecf02d5adec11e7e7b3e2f5581ae57c3e99c08fd6fc48098accf67764",
	} {
		f.Add(hexBytes(f, seed))
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		assertSignedRoundTrip(t, &TxLegacy{}, nil, payload)
	})
}

func FuzzTxEIP2930FromRLP(f *testing.F) {
	for _, seed := range []string{
		// ethereum/tests v17.2 TransactionTests/ttEIP2930/accessListStorage32Bytes.json
		"0x01f89a018001826a4094095e7baea6a6c7c4c2dfeb977efac326af552d878080f838f794a95e7baea6a6c7c4c2dfeb977efac326af552d87e1a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36",
		// ethereum/tests v17.2 TransactionTests/ttEIP2930/accessListAddressGreaterThan20.json
		"0x01f8be018001826a4094095e7baea6a6c7c4c2dfeb977efac326af552d878080f85cf85a95b94f5374fce5edbc8e2a8697c15331677e6ebf0b1cf842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000180a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36",
	} {
		f.Add(hexBytes(f, seed)[1:])
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		assertSignedRoundTrip(t, &TxEIP2930{}, []byte{Transaction2930}, payload)
	})
}

func FuzzTxEIP1559FromRLP(f *testing.F) {
	// ethereum/tests v17.2 TransactionTests/ttEIP1559/GasLimitPriceProductOverflowtMinusOne.json
	f.Add(hexBytes(f, "0x02f885018084773594009f02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82520894095e7baea6a6c7c4c2dfeb977efac326af552d878080c080a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36")[1:])

	f.Fuzz(func(t *testing.T, payload []byte) {
		assertSignedRoundTrip(t, &TxEIP1559{}, []byte{Transaction1559}, payload)
	})
}

func FuzzTxEIP4844FromRLP(f *testing.F) {
	// ethereum/tests v17.2 blockWithAllTransactionTypes_Cancun, type 3 tx
	f.Add(hexBytes(f, "0x03f8890103018203e885e8d4a5100094100000000000000000000000000000000000000a0780c00ae1a001a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8809f638144c46d5de7a9e630c0e7c5c63ae829ecfd8cc94715d9c29fe17c464de0a06c5fc54c3aa868ba35ef31a4e12431611631ab7bcdceb4214dd273d83f73b5e1")[1:])

	f.Fuzz(func(t *testing.T, payload []byte) {
		assertSignedRoundTrip(t, &TxEIP4844{}, []byte{Transaction4844}, payload)
	})
}

func FuzzTxEIP7702FromRLP(f *testing.F) {
	for _, seed := range []string{
		// EEST tests@v21.0.2 valid_tx_invalid_auth_signature.json, r=0
		"0x04f880018080078407270e00946280aceac5db12798d67870e2447ac01ab4e316a8080c0dbda019400000000000000000000000000000000000000008001800180a04763d5a7011dc615eb6682c7bdb9492bd48cddc3bc59e6a24653cfa031885d98a01cb2b4c89661dbd91f6653c13a55019f5f71061a408f6bd304697e68ee04aacc",
		// EEST tests@v21.0.2 invalid_tx_invalid_nonce_encoding.json, non_zero_address
		"0x04f8c301808007830186a09400000000000000000000000000000000000000008080c0f85ef85c8094000000000000000000000000000000000000000182000001a0102f8433dce557de25f5459c65c55c37f04e38e8a3e1452ba7acdaac39aa3663a0772dc99ee2144c63fd630717676ae7828fcc5ab8604a62e7856bc48ce59d1ff680a09e6ce2dc936e7d6d98d954608301d5c640a4928a09848076f77f36ee1b6f9f4fa060e7220a371a1f530eeb7735e64c1b620939dfc2b835f05d9cb312682197d46f",
	} {
		f.Add(hexBytes(f, seed)[1:])
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		assertSignedRoundTrip(t, &TxEIP7702{}, []byte{Transaction7702}, payload)
	})
}
