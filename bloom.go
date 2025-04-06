package ethtypes

import (
	"encoding/binary"

	"github.com/sig-0/ethtypes/keccak"
)

const BloomByteLength = 256

// Bloom represents an Ethereum bloom filter (for logs)
type Bloom [BloomByteLength]byte

// NewBloom creates an empty Ethereum bloom filter
func NewBloom() Bloom {
	return Bloom{}
}

// SetBytes sets the bloom filter from a byte slice
func (b *Bloom) SetBytes(data []byte) {
	if len(data) != BloomByteLength {
		return
	}

	copy(b[:], data)
}

// Add adds the given data to the bloom filter
func (b *Bloom) Add(data []byte) {
	// Generate the Keccak-256 hash of the data
	hash := keccak.New().Hash(data)

	// Set 3 bits in the bloom filter based on the hash
	for idx := 0; idx < 6; idx += 2 {
		// Obtain the least significant 11 bits from the pair of bytes (16 bits)
		bitToSet := uint(binary.BigEndian.Uint16(hash[idx:idx+2])) & 0x07FF

		// Invert the bit position (as in the Ethereum spec)
		bitIndex := 0x07FF - bitToSet

		// Calculate byte and bit position
		byteIndex := bitIndex / 8
		bitPosition := 7 - (bitIndex % 8) // MSB ordering within byte

		// Set the bit
		b[byteIndex] |= 1 << bitPosition
	}
}

// Test checks if the given data might be in the bloom filter
// Returns:
//   - true: data might be in the set (possible false positive)
//   - false: data is definitely not in the set
func (b *Bloom) Test(data []byte) bool {
	// Generate the Keccak-256 hash of the data
	hash := keccak.New().Hash(data)

	// Check if all 3 bits are set in the bloom filter
	for idx := 0; idx < 6; idx += 2 {
		// Calculate the same bit position as in Add
		bitToSet := uint(binary.BigEndian.Uint16(hash[idx:idx+2])) & 0x07FF
		bitIndex := 0x07FF - bitToSet

		// Calculate byte and bit position
		byteIndex := bitIndex / 8
		bitPosition := 7 - (bitIndex % 8) // MSB ordering within byte

		// If any of the required bits is not set, return false
		if (b[byteIndex] & (1 << bitPosition)) == 0 {
			return false
		}
	}

	// All three bits are set
	return true
}

// ToBytes returns the bloom filter as a byte slice (256 bytes)
func (b *Bloom) ToBytes() []byte {
	bytes := make([]byte, BloomByteLength)
	copy(bytes, b[:])

	return bytes
}

// TestLog checks if the given log is in the bloom.
// It checks against:
//   - the log address
//   - each topic
func (b *Bloom) TestLog(log *Log) bool {
	// Check if the log address is set
	if !b.Test(log.Address.ToBytes()) {
		return false
	}

	// Check if all topics are present
	for _, topic := range log.Topics {
		if !b.Test(topic.ToBytes()) {
			return false
		}
	}

	return true
}

// LogsBloom obtains the logs bloom from a list of log entries.
// The address and each topic of a log are added to the bloom filter
func LogsBloom(logs []*Log) Bloom {
	b := NewBloom()

	for _, log := range logs {
		// Add the address
		b.Add(log.Address.ToBytes())

		// Add each topic
		for _, topic := range log.Topics {
			b.Add(topic.ToBytes())
		}
	}

	return b
}

// BytesToBloom sets the bloom filter from a byte slice.
// If the input is not exactly 256 bytes, an empty bloom is returned
func BytesToBloom(data []byte) Bloom {
	b := NewBloom()

	b.SetBytes(data)

	return b
}
