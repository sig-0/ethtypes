package ethtypes

import (
	"github.com/bits-and-blooms/bloom/v3"
)

const bloomSize = 256 // Bytes

// Bloom represents an Ethereum bloom filter (for logs)
type Bloom struct {
	filter *bloom.BloomFilter
}

// NewBloom creates a new bloom filter with Ethereum's standard parameters
func NewBloom() *Bloom {
	// Ethereum uses a 2048-bit bloom filter (256 bytes),
	// so the false positive rate is adjusted accordingly (num. of hash functions)
	filter := bloom.NewWithEstimates(bloomSize*8, 0.01) // 2048 items with 1% false positive rate

	return &Bloom{
		filter: filter,
	}
}

// BytesToBloom converts a byte slice to a Bloom filter.
// If the deserialization fails, an empty bloom is returned
func BytesToBloom(data []byte) *Bloom {
	if len(data) == 0 {
		return NewBloom()
	}

	// Create a new bloom filter
	b := NewBloom()

	// Parse the data
	if err := b.filter.UnmarshalBinary(data); err != nil {
		return NewBloom()
	}

	return b
}

// ToBytes serializes the bloom filter.
// In case of an error, returns an empty bloom
func (b *Bloom) ToBytes() []byte {
	data, err := b.filter.MarshalBinary()
	if err != nil {
		return make([]byte, bloomSize)
	}

	// Ensure the output is exactly 256 bytes
	result := make([]byte, bloomSize)

	copy(result, data)

	return result
}

// Add adds data to the bloom filter
func (b *Bloom) Add(data []byte) {
	b.filter.Add(data)
}

// Test checks if data might be in the bloom filter
func (b *Bloom) Test(data []byte) bool {
	return b.filter.Test(data)
}
