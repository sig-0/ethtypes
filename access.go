package ethtypes

type AccessListEntry struct {
	StorageKeys []Hash
	Address     Address
	GasUsed     uint64
}
