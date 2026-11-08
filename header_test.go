package ethtypes

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/hex"
	"github.com/sig-0/ethtypes/keccak"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hexBytes(tb testing.TB, s string) []byte {
	tb.Helper()

	b, err := hex.FromHexString(s)
	require.NoError(tb, err)

	return b
}

func TestHeaderHashMainnet(t *testing.T) {
	t.Parallel()

	// One real mainnet header per fork, with its block hash from
	// eth_getBlockByNumber (https://ethereum-rpc.publicnode.com)
	testTable := []struct {
		header headerData
		name   string
		hash   Hash
	}{
		{
			// Mainnet genesis block 0
			name: "genesis",
			hash: StringToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
			header: &HeaderLegacy{
				UncleHash:        ZeroOmmerHash,
				StateRoot:        StringToHash("0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544"),
				TransactionsRoot: ZeroStorageHash,
				ReceiptsRoot:     ZeroStorageHash,
				Difficulty:       0x400000000,
				GasLimit:         0x1388,
				ExtraData:        hexBytes(t, "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
				Nonce:            0x42,
			},
		},
		{
			// Mainnet block 12965000, first London block
			name: "london",
			hash: StringToHash("0x9b83c12c69edb74f6c8dd5d052765c1adf940e320bd1291696e6fa07829eee71"),
			header: &HeaderEIP1559{
				ParentHash:       StringToHash("0x3de6bb3849a138e6ab0b83a3a00dc7433f1e83f7fd488e4bba78f2fe2631a633"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x7777788200b672a42421017f65ede4fc759564c8"),
				StateRoot:        StringToHash("0x41cf6e8e60fd087d2b00360dc29e5bfb21959bce1f4c242fd1ad7c4da968eb87"),
				TransactionsRoot: StringToHash("0xdfcb68d3a3c41096f4a77569db7956e0a0e750fad185948e54789ea0e51779cb"),
				ReceiptsRoot:     StringToHash("0x8a8865cd785e2e9dfce7da83aca010b10b9af2abbd367114b236f149534c821d"),
				LogsBloom:        BytesToBloom(hexBytes(t, "0x24e74ad77d9a2b27bdb8f6d6f7f1cffdd8cfb47fdebd433f011f7dfcfbb7db638fadd5ff66ed134ede2879ce61149797fbcdf7b74f6b7de153ec61bdaffeeb7b59c3ed771a2fe9eaed8ac70e335e63ff2bfe239eaff8f94ca642fdf7ee5537965be99a440f53d2ce057dbf9932be9a7b9a82ffdffe4eeee1a66c4cfb99fe4540fbff936f97dde9f6bfd9f8cefda2fc174d23dfdb7d6f7dfef5f754fe6a7eec92efdbff779b5feff3beafebd7fd6e973afebe4f5d86f3aafb1f73bf1e1d0cdd796d89827edeffe8fb6ae6d7bf639ec5f5ff4c32f31f6b525b676c7cdf5e5c75bfd5b7bd1928b6f43aac7fa0f6336576e5f7b7dfb9e8ebbe6f6efe2f9dfe8b3f56")),
				Difficulty:       0x1b81c1fe05b218,
				Number:           0xc5d488,
				GasLimit:         0x1ca3542,
				GasUsed:          0x1ca2629,
				Timestamp:        0x610bdaa6,
				ExtraData:        hexBytes(t, "0x68747470733a2f2f7777772e6b7279707465782e6f7267"),
				MixDigest:        StringToHash("0x9620b46a81a4795cf4449d48e3270419f58b09293a5421205f88179b563f815a"),
				Nonce:            0xb223da049adf2216,
				BaseFeePerGas:    big.NewInt(0x3b9aca00),
			},
		},
		{
			// Mainnet block 15537394, first Paris (proof-of-stake) block
			name: "paris",
			hash: StringToHash("0x56a9bb0302da44b8c0b3df540781424684c3af04d0b7a38d72842b762076a664"),
			header: &HeaderEIP1559{
				ParentHash:       StringToHash("0x55b11b918355b1ef9c5db810302ebad0bf2544255b530cdce90674d5887bb286"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0xeee27662c2b8eba3cd936a23f039f3189633e4c8"),
				StateRoot:        StringToHash("0x40c07091e16263270f3579385090fea02dd5f061ba6750228fcc082ff762fda7"),
				TransactionsRoot: StringToHash("0x1ea1746468686159ce730c1cc49a886721244e5d1fa9a06d6d4196b6f013c82c"),
				ReceiptsRoot:     StringToHash("0x928073fb98ce316265ea35d95ab7e2e1206cecd85242eb841dbbcc4f568fca4b"),
				LogsBloom:        BytesToBloom(hexBytes(t, "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				Number:           0xed14f2,
				GasLimit:         0x1c9c380,
				GasUsed:          0x1c9811e,
				Timestamp:        0x6322c973,
				MixDigest:        StringToHash("0xa86c2e601b6c44eb4848f7d23d9df3113fbcac42041c49cbed5000cb4f118777"),
				BaseFeePerGas:    big.NewInt(0xb5d68e0a3),
			},
		},
		{
			// Mainnet block 17034870, first Shanghai block
			name: "shanghai",
			hash: StringToHash("0xe22c56f211f03baadcc91e4eb9a24344e6848c5df4473988f893b58223f5216c"),
			header: &HeaderEIP4895{
				ParentHash:       StringToHash("0xc2558f8143d5f5acb8382b8cb2b8e2f1a10c8bdfeededad850eaca048ed85d8f"),
				UncleHash:        ZeroOmmerHash,
				Coinbase:         StringToAddress("0x388c818ca8b9251b393131c08a736a67ccb19297"),
				StateRoot:        StringToHash("0x7fd42f5027bc18315b3781e65f19e4c8828fd5c5fce33410f0fb4fea0b65541f"),
				TransactionsRoot: StringToHash("0x6f235d618461c08943aa5c23cc751310d6177ab8a9b9a7b66ffa637d988680e6"),
				ReceiptsRoot:     StringToHash("0xe0ac34bafdd757bcca2dea27a3fc5870dd0836998877e29361c1fc55e19416ec"),
				LogsBloom:        BytesToBloom(hexBytes(t, "0xb06769bc11f4d7a51a3bc4bed59367b75c32d1bd79e5970e73732ac0eed0251af0e2abc8811fc1b4c5d45a4a4eb5c5af9e73cc9a8be6ace72faadc03536d6b69fcdf80116fd89f7efbdbf38ff957e8f6ae83ccac60cf4b7c8b1c9487bebfa8ed6e42297e17172d5b678dd3f283b22f49bbf4a0565eb93d9d797b2f9a0adaff9813af53d6fffa71d5a6fb056ab73ca87659dc97c19f99839c6c3138e527161b4dfee8b1f64d42f927abc745f3ff168e8e9510e2e079f4868ba8ff94faf37c9a7947a43c1b4c931dfbef88edeb2d7ede5ceaebc85095cfbbd206646def0138683b687fa63fdf22898260d616bc714d698bc5748c7a5bff0a4a32dd797596a794a0")),
				Number:           0x103ee76,
				GasLimit:         0x1c9c380,
				GasUsed:          0x1c9bfe2,
				Timestamp:        0x6437306f,
				ExtraData:        hexBytes(t, "0xd883010b05846765746888676f312e32302e32856c696e7578"),
				MixDigest:        StringToHash("0x812ed704cc408c435c7baa6e86296c1ac654a139ae8c4a26d6460742b951d4f9"),
				BaseFeePerGas:    big.NewInt(0x42fbae6d5),
				WithdrawalsRoot:  ZeroStorageHash,
			},
		},
		{
			// Mainnet block 19426587, first Cancun block
			name: "cancun",
			hash: StringToHash("0xf8e2f40d98fe5862bc947c8c83d34799c50fb344d7445d020a8a946d891b62ee"),
			header: &HeaderEIP4844{
				ParentHash:            StringToHash("0xdb672c41cfd47c84ddb478ffde5a09b76964f77dceca0e62bdf719c965d73e7f"),
				UncleHash:             ZeroOmmerHash,
				Coinbase:              StringToAddress("0xdae56d85ff707b3d19427f23d8b03b7b76da1006"),
				StateRoot:             StringToHash("0xbd33ab68095087d81beb810b3f5d0b16050b3f798ae3978e440bab048dd78992"),
				TransactionsRoot:      StringToHash("0x20cbdd2cd6113eb72dade6be7ec18fe6a7167a8a0af912a2171af909a8cda9f6"),
				ReceiptsRoot:          StringToHash("0x59c3691e83e0ddeafeedd07f5e30850cc6c963e85327aa1201fbe1f731ff3dbc"),
				LogsBloom:             BytesToBloom(hexBytes(t, "0x0021000000000001080801008000320000000060000000000005000080c200040000100000006002440409000000010402011000890200000a201000042800440442148c0100208408004009012000200000040801644808800000600029068004012001020000002510000000020900c8122010020284000080021006000101000000401810621c0040000000001010000004800100404808000640255000002201000010002000000040c0000000000400a004000c0000884000304e00202400100402000000004204000004041008005600001000001000000003015030120012280000022020910040429204408020009000000010120000400000000400")),
				Number:                0x1286d1b,
				GasLimit:              0x1c9c380,
				GasUsed:               0x2830cd,
				Timestamp:             0x65f1b057,
				ExtraData:             hexBytes(t, "0xd883010d0e846765746888676f312e32312e37856c696e7578"),
				MixDigest:             StringToHash("0x2617b147c1b3cf43a28d08d508ab2d8860c6cf40da58837676cfaaf4f9e07f62"),
				BaseFeePerGas:         big.NewInt(0xe6ca77a30),
				WithdrawalsRoot:       StringToHash("0x6c119891018ed3a43d04197a8eb94d85f287304b8ace21b08e9f68cbd2f8de61"),
				ParentBeaconBlockRoot: StringToHash("0xb35bb80bc5f4e3d8f19b62f6274add24dca334db242546c3024403027aaf6412"),
			},
		},
		{
			// Mainnet block 22431084, first Prague block
			name: "prague",
			hash: StringToHash("0x50c8cab760b2948349c590461b166773c45d8f4858cccf5a43025ab2960152e8"),
			header: &HeaderEIP7685{
				ParentHash:            StringToHash("0x28fb2c1d988435955e569451c6ad772f7fb5e61cddd7463c7b60e933ed5ff237"),
				UncleHash:             ZeroOmmerHash,
				Coinbase:              StringToAddress("0xe688b84b23f322a994a53dbf8e15fa82cdb71127"),
				StateRoot:             StringToHash("0x49d29cd525c7a9f4a33c1e2debc7529f24757c81f689b7276b70018333761b53"),
				TransactionsRoot:      StringToHash("0x6522a2eba58778c64f0facee1378ddcdb1b5927285f461f9a8314c1b5fe1e5b1"),
				ReceiptsRoot:          StringToHash("0xf2260e554d7827e222789d9851f5f8a8a9bc78b1e81ea68da7314622f049924b"),
				LogsBloom:             BytesToBloom(hexBytes(t, "0x1c2d14628013080620b50320a0885ae80185204a6c4841040101d009c41060fb05358520a00d00a540113a514a9e511c83350a088c22223c9281008042a800c40620120e024a19384a006b8856d324a4f0067931056c0d2c1d1072db844081406c4403ade3688228ef2e3ac201984e860e0163601130a7d2032d269401d9314008a8c14f4340130c4859105c0381a30d011902f175982858ad3c30fba23c55fa4b40003aa5c1688b4911a2e09c84e4213436420d50568100001d44080c8001d900a51c6252d429938181c431a0080b17c9342866c40c14d700853586c59a291632736c124b23800a00c6060c25d17e68a5301070438916505419a0550429469d")),
				Number:                0x156456c,
				GasLimit:              0x22550dd,
				GasUsed:               0x9d8f63,
				Timestamp:             0x681b3057,
				ExtraData:             hexBytes(t, "0xd883010f0b846765746888676f312e32342e32856c696e7578"),
				MixDigest:             StringToHash("0xef1ed97e3e0205c73f287f22c5900944da077daaadad17f57355fe7705cf3b05"),
				BaseFeePerGas:         big.NewInt(0x548795d3),
				WithdrawalsRoot:       StringToHash("0xc4f495225a2ac0cd4052c3493b36e96d0efe46eb0650ed124a9627f1badcc935"),
				BlobGasUsed:           0x120000,
				ExcessBlobGas:         0x3020000,
				ParentBeaconBlockRoot: StringToHash("0x947d22746be643f1428031a9ab7c58776ca54e461903bb5e4ba8a73448552967"),
				RequestsHash:          StringToHash("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
		},
		{
			// Mainnet block 23935694, first Osaka (Fusaka) block
			name: "osaka",
			hash: StringToHash("0x8281db4990564caca17e620a70847c7b001ad70cd7bb5e64aa78adea16747677"),
			header: &HeaderEIP7685{
				ParentHash:            StringToHash("0xe739e49cf9f9f704e0f9e0cbe7174b63e3704b6b57c83575d783e1acb578f704"),
				UncleHash:             ZeroOmmerHash,
				Coinbase:              StringToAddress("0x396343362be2a4da1ce0c1c210945346fb82aa49"),
				StateRoot:             StringToHash("0xa852ef67db7acd739779aa1dbf96d6919b54b99cde5de7945b57a4a17e2c901b"),
				TransactionsRoot:      StringToHash("0x79d5157ca8347d4d27fedc92d417d986f92858d8f4bfebf8fe49a11a0df38534"),
				ReceiptsRoot:          StringToHash("0x9e7fe0132055811314808fde708b76ea2e119cff98682b5994725d5720ce90d9"),
				LogsBloom:             BytesToBloom(hexBytes(t, "0xfffdfffffffffffffffffffffffffffffffffffffffffffffffffbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffff")),
				Number:                0x16d3ace,
				GasLimit:              0x392a1ae,
				GasUsed:               0x1fe3120,
				Timestamp:             0x6930b063,
				ExtraData:             hexBytes(t, "0xe29ca82051756173617220287175617361722e77696e2920e29ca8"),
				MixDigest:             StringToHash("0x2daccc66aa6ca9cb45b1498ab06252267018d50a30e5a399e588b1bd8f8553fb"),
				BaseFeePerGas:         big.NewInt(0x1df20bc),
				WithdrawalsRoot:       StringToHash("0x31f85c322b8a666c7e53c763bb2f23aca32ad0c3074f43b0ba9075a1da94720f"),
				BlobGasUsed:           0x120000,
				ExcessBlobGas:         0x60000,
				ParentBeaconBlockRoot: StringToHash("0x24f825d13a58c2aef66786519c48477b475672506538a610441d17d405889f2b"),
				RequestsHash:          StringToHash("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.hash, NewHeader(testCase.header).Hash())

			pb, err := NewHeader(testCase.header).ToProto()
			require.NoError(t, err)
			assert.Equal(t, testCase.hash.ToBytes(), pb.GetHash())

			got := &Header{}
			require.NoError(t, got.FromProto(pb))

			assert.Equal(t, testCase.header.getType(), got.inner.getType())
			assert.Equal(t, testCase.hash, got.Hash())
			assert.Equal(t, testCase.header.getBlobGasUsed(), got.BlobGasUsed())
			assert.Equal(t, testCase.header.getExcessBlobGas(), got.ExcessBlobGas())
			assert.Equal(t, testCase.header.getParentBeaconBlockRoot(), got.ParentBeaconBlockRoot())
			assert.Equal(t, testCase.header.getRequestsHash(), got.RequestsHash())
		})
	}
}

func TestHeaderEIPConstants(t *testing.T) {
	t.Parallel()

	// EIP-3675, "Specification": post-merge ommersHash is keccak256(rlp([]))
	assert.Equal(t, BytesToHash(keccak.New().Hash([]byte{0xc0})), ZeroOmmerHash)
	assert.Equal(t, StringToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"), ZeroOmmerHash)

	// EIP-7685, "Block header": requests_hash of no requests is sha256("")
	assert.Equal(t,
		StringToHash("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		Hash(sha256.Sum256(nil)),
	)
}

func TestHeaderFromProtoResetsHash(t *testing.T) {
	t.Parallel()

	header := NewHeader(&HeaderLegacy{Number: 1})
	usedHash := header.Hash() // cached

	other := NewHeader(&HeaderEIP1559{Number: 2, BaseFeePerGas: big.NewInt(7)})

	pb, err := other.ToProto()
	require.NoError(t, err)
	require.NoError(t, header.FromProto(pb))

	assert.Equal(t, other.Hash(), header.Hash())
	assert.NotEqual(t, usedHash, header.Hash())
}

func TestHeaderProtoErrors(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, (&Header{}).FromProto(nil), ErrNilProtoHeader)

	shanghai := &ethProto.Header{Payload: &ethProto.Header_Eip4895{Eip4895: &ethProto.EIP4895Payload{}}}

	testTable := []struct {
		header interface{ FromProto(*ethProto.Header) error }
		name   string
	}{
		{name: "cancun", header: &HeaderEIP4844{}},
		{name: "prague", header: &HeaderEIP7685{}},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			require.ErrorIs(t, testCase.header.FromProto(nil), ErrNilProtoHeader)
			require.ErrorIs(t, testCase.header.FromProto(shanghai), ErrInvalidHeaderPayload)
			require.ErrorIs(t, testCase.header.FromProto(&ethProto.Header{}), ErrInvalidHeaderPayload)
		})
	}

	t.Run("nil cancun payload", func(t *testing.T) {
		t.Parallel()

		h := &Header{}
		require.NoError(t, h.FromProto(&ethProto.Header{Payload: &ethProto.Header_Eip4844{}}))
		assert.Equal(t, headerEIP4844, h.inner.getType())
	})
}

func TestHeaderNilBaseFee(t *testing.T) {
	t.Parallel()

	testTable := []struct {
		header interface {
			headerData
			ToRLP() []byte
			ToProto() *ethProto.Header
		}
		name  string
		items int
	}{
		{name: "cancun zero value", header: &HeaderEIP4844{}, items: 20},
		{name: "prague zero value", header: &HeaderEIP7685{}, items: 21},
	}

	for _, testCase := range testTable {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			v, err := ethrlp.DecodeBytes(testCase.header.ToRLP())
			require.NoError(t, err)

			items, ok := v.GetValue().([]ethrlp.Value)
			require.True(t, ok)
			require.Len(t, items, testCase.items)

			// baseFeePerGas is item 15 (nil is encoded as 0x80)
			baseFee, ok := items[15].GetValue().([]byte)
			require.True(t, ok)
			assert.Empty(t, baseFee)

			hash := NewHeader(testCase.header).Hash()
			assert.Equal(t, hash.ToBytes(), testCase.header.ToProto().GetHash())
		})
	}
}
