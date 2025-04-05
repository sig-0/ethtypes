package ethtypes

// Block is a single Ethereum block, containing the
// header and transactions
type Block struct {
	Header       *Header        // the block header
	Transactions []*Transaction // the full transaction set
}
