package types

type Header struct {
	ParentHash       Hash
	UncleHash        Hash
	Beneficiary      Address
	StateRoot        Hash
	TransactionsRoot Hash
	ReceiptsRoot     Hash
	LogsBloom        Bloom
	Difficulty       uint64
	Number           uint64
	GasLimit         uint64
	GasUsed          uint64
	Time             uint64
	MixDigest        Hash
	Nonce            Nonce
}
