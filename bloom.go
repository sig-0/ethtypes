package ethtypes

const (
	bloomSize = 256 // Bytes
)

type Bloom [bloomSize]byte

func (b Bloom) ToBytes() []byte {
	return b[:]
}
