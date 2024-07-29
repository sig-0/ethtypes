//nolint:unused // Currently unused
package types

type Block struct {
	header       *Header
	transactions []*Transaction
}

type Nonce [8]byte
