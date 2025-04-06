package ethtypes

import (
	"testing"
)

func generateBloomTestData(b *testing.B, count int) [][]byte {
	b.Helper()

	data := make([][]byte, count)
	for i := 0; i < count; i++ {
		data[i] = []byte("test-data-" + string(rune('a'+i%26)) + "-" + string(rune('0'+i%10)))
	}

	return data
}

func benchmarkBloomAddCommon(b *testing.B, count int) {
	b.Helper()

	testData := generateBloomTestData(b, count)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		bloom := NewBloom()

		for _, data := range testData {
			bloom.Add(data)
		}
	}
}

func benchmarkBloomTestCommon(b *testing.B, count int) {
	b.Helper()

	testData := generateBloomTestData(b, count)
	bloom := NewBloom()

	for _, data := range testData {
		bloom.Add(data)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for j := 0; j < 10; j++ {
			bloom.Test(testData[j%len(testData)])
		}
	}
}

func BenchmarkBloom_Add10(b *testing.B) {
	benchmarkBloomAddCommon(b, 10)
}

func BenchmarkBloom_Add100(b *testing.B) {
	benchmarkBloomAddCommon(b, 100)
}

func BenchmarkBloom_Add1000(b *testing.B) {
	benchmarkBloomAddCommon(b, 1000)
}

func BenchmarkBloom_Add10000(b *testing.B) {
	benchmarkBloomAddCommon(b, 10000)
}

func BenchmarkBloom_Test10(b *testing.B) {
	benchmarkBloomTestCommon(b, 10)
}

func BenchmarkBloom_Test100(b *testing.B) {
	benchmarkBloomTestCommon(b, 100)
}

func BenchmarkBloom_Test1000(b *testing.B) {
	benchmarkBloomTestCommon(b, 1000)
}

func BenchmarkBloom_Test10000(b *testing.B) {
	benchmarkBloomTestCommon(b, 10000)
}
