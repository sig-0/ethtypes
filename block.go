//nolint:unused // Currently unused
package ethtypes

type Block struct {
	header       *Header
	transactions []*Transaction
}

type Nonce [8]byte
