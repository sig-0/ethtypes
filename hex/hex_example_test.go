package hex

import (
	"fmt"
	"math/big"
	"strings"
)

func ExampleToHexString() {
	var (
		input  = []byte("random data")
		result = ToHexString(input)
	)

	fmt.Println(result)
	// Output: 0x72616e646f6d2064617461
}

func ExampleFromHexString() {
	var (
		input   = []byte("random data")
		encoded = ToHexString(input)
	)

	result, err := FromHexString(encoded)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(result))
	// Output: random data
}

func ExampleFromUintToHex() {
	var (
		input  = uint64(100)
		result = FromUintToHex(input)
	)

	fmt.Println(result)
	// Output: 0x64
}

func ExampleFromBigToHex() {
	var (
		input  = big.NewInt(100)
		result = FromBigToHex(input)
	)

	fmt.Println(result)
	// Output: 0x64
}

func ExampleDecodeHexToUint() {
	var (
		input   = uint64(100)
		encoded = FromUintToHex(input)
	)

	decoded, err := DecodeHexToUint(encoded)
	if err != nil {
		panic(err)
	}

	fmt.Println(decoded)
	// Output: 100
}

func ExampleDecodeHexToBig() {
	var (
		input   = big.NewInt(100)
		encoded = FromBigToHex(input)
	)

	decoded, err := DecodeHexToBig(encoded)
	if err != nil {
		panic(err)
	}

	fmt.Println(decoded.String())
	// Output: 100
}

func ExampleDecodeString() {
	var (
		input   = []byte("random data")
		encoded = ToHexString(input)
	)

	// DecodeString expects the input without the 0x prefix
	decoded, err := DecodeString(
		strings.TrimPrefix(encoded, "0x"),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(decoded))
	// Output: random data
}
