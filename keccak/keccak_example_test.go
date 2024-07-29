package keccak

import "fmt"

func ExampleKeccak256_Hash() {
	var (
		input = []byte("random data")
		h     = New()
	)

	result := h.Hash(input)

	fmt.Printf("%x", result)
	// Output: 6d4cca48b4c25bd111efc7f5a67b9d36e287fdb84246c12ae4e0f61190047dc3
}
