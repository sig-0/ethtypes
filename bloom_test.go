package ethtypes

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBloom_Add(t *testing.T) {
	t.Parallel()

	bloom := NewBloom()

	// Test with a few sample values
	testData := [][]byte{
		[]byte("test data 1"),
		[]byte("test data 2"),
		[]byte("ethereum"),
		[]byte("bloom filter"),
	}

	// Add each value to the bloom filter
	for _, data := range testData {
		bloom.Add(data)
	}

	// Verify each value matches
	for _, data := range testData {
		assert.True(t, bloom.Test(data))
	}
}

func TestBloom_SetBytes(t *testing.T) {
	t.Parallel()

	t.Run("valid bytes", func(t *testing.T) {
		t.Parallel()

		bloom := NewBloom()

		// Add some data
		testData := [][]byte{
			[]byte("ethereum"),
			[]byte("bloom"),
			[]byte("filter"),
		}

		for _, data := range testData {
			bloom.Add(data)
		}

		// Get bytes representation
		serializedBloom := bloom.ToBytes()
		require.Equal(t, BloomByteLength, len(serializedBloom))

		// Create a new bloom filter and set from bytes
		otherBloom := BytesToBloom(serializedBloom)

		// Verify both filters behave identically
		for _, data := range testData {
			assert.Equal(t, bloom.Test(data), otherBloom.Test(data))
		}

		// Check if bytes match
		serializedOtherBloom := otherBloom.ToBytes()
		assert.Equal(t, serializedBloom, serializedOtherBloom)
	})

	t.Run("invalid length", func(t *testing.T) {
		t.Parallel()

		// Try to set bytes with invalid length
		invalidBytes := make([]byte, BloomByteLength-1) // One byte too short
		bloom := BytesToBloom(invalidBytes)

		// Verify the bloom filter is empty
		assert.Zero(t, bloom)
	})
}

func TestBloom_LogsBloom(t *testing.T) {
	t.Parallel()

	generateAddresses := func(count int) []Address {
		addrs := make([]Address, 0, count)

		for i := range count {
			addrs = append(
				addrs,
				StringToAddress(fmt.Sprintf("0x%d", i)),
			)
		}

		return addrs
	}

	generateTopics := func(count int) []Hash {
		topics := make([]Hash, 0, count)

		for i := range count {
			topics = append(
				topics,
				StringToHash(fmt.Sprintf("topic %d", i)),
			)
		}

		return topics
	}

	t.Run("included logs", func(t *testing.T) {
		t.Parallel()

		var (
			addrs  = generateAddresses(2)
			topics = generateTopics(2)

			logs = []*Log{
				{
					Address: addrs[0],
					Topics:  topics[:1],
					Data:    []byte("data1"),
				},
				{
					Address: addrs[1],
					Topics:  topics,
					Data:    []byte("data2"),
				},
			}
		)

		// Generate logs bloom
		bloom := LogsBloom(logs)

		// Verify all addresses and topics are in the bloom
		for _, addr := range addrs {
			assert.True(t, bloom.Test(addr.ToBytes()))
		}

		for _, topic := range topics {
			assert.True(t, bloom.Test(topic.ToBytes()))
		}

		// Verify each log passes the bloom filter test
		for _, log := range logs {
			assert.True(t, bloom.TestLog(log))
		}
	})

	t.Run("missing logs", func(t *testing.T) {
		t.Parallel()

		var (
			addrs  = generateAddresses(2)
			topics = generateTopics(2)

			logs = []*Log{
				{
					Address: addrs[0],
					Topics:  topics[:1],
					Data:    []byte("data1"),
				},
				{
					Address: addrs[1],
					Topics:  topics,
					Data:    []byte("data2"),
				},
			}
		)

		// Add the first log, but no the second one
		bloom := LogsBloom(logs[:1])

		assert.True(t, bloom.TestLog(logs[0]))
		assert.False(t, bloom.TestLog(logs[1]))
	})
}
