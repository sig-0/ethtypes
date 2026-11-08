package ethtypes

import (
	"fmt"
	"math/big"
	"sync/atomic"

	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

type headerType byte

// Header types are ordered by hardfork (Block.ToRLP relies on it)
const (
	headerLegacy  headerType = 0x0
	headerEIP1559 headerType = 0x1
	headerEIP4895 headerType = 0x2
	headerEIP4844 headerType = 0x3
	headerEIP7685 headerType = 0x4
)

// Header is the
type Header struct {
	inner headerData

	// Quick lookup
	hash atomic.Value
}

// headerData is the wrapper for specific transaction types
// such as legacy, EIP-1559 and EIP-4895
type headerData interface {
	// Common header types //

	getType() headerType
	getHash() Hash
	getParentHash() Hash
	getUncleHash() Hash
	getStateRoot() Hash
	getTransactionsRoot() Hash
	getReceiptsRoot() Hash
	getMixDigest() Hash
	getCoinbase() Address
	getLogsBloom() Bloom
	getExtraData() []byte
	getDifficulty() uint64
	getNumber() uint64
	getGasLimit() uint64
	getGasUsed() uint64
	getTimestamp() int64
	getNonce() uint64

	// EIP-1559 + EIP-4895 //
	getBaseFeePerGas() *big.Int

	// EIP-4895 //
	getWithdrawalsRoot() Hash

	// EIP-4844 //
	getBlobGasUsed() uint64
	getExcessBlobGas() uint64
	getParentBeaconBlockRoot() Hash

	// EIP-7685 //
	getRequestsHash() Hash
}

// NewHeader creates a new header wrapper
func NewHeader(inner headerData) *Header {
	return &Header{
		inner: inner,
	}
}

func (h *Header) Hash() Hash {
	// Load the hash from the built-in type cache
	// for quick lookup, if it's present
	if hashRaw := h.hash.Load(); hashRaw != nil {
		hash, _ := hashRaw.(Hash)

		return hash
	}

	// Calculate the header (block) hash
	hash := h.inner.getHash()

	// Update the builtin header (block) cache
	h.hash.Store(hash)

	return hash
}

// ToRLP encodes the header using RLP encoding
func (h *Header) ToRLP() ([]byte, error) {
	switch h.inner.getType() {
	case headerLegacy:
		header := h.inner.(*HeaderLegacy)

		return header.ToRLP(), nil
	case headerEIP1559:
		header := h.inner.(*HeaderEIP1559)

		return header.ToRLP(), nil
	case headerEIP4895:
		header := h.inner.(*HeaderEIP4895)

		return header.ToRLP(), nil
	case headerEIP4844:
		header := h.inner.(*HeaderEIP4844)

		return header.ToRLP(), nil
	case headerEIP7685:
		header := h.inner.(*HeaderEIP7685)

		return header.ToRLP(), nil
	}

	return nil, fmt.Errorf("unknown header type, %x", h.inner.getType())
}

func (h *Header) ParentHash() Hash {
	return h.inner.getParentHash()
}

func (h *Header) UncleHash() Hash {
	return h.inner.getUncleHash()
}

func (h *Header) StateRoot() Hash {
	return h.inner.getStateRoot()
}

func (h *Header) TransactionsRoot() Hash {
	return h.inner.getTransactionsRoot()
}

func (h *Header) ReceiptsRoot() Hash {
	return h.inner.getReceiptsRoot()
}

func (h *Header) MixDigest() Hash {
	return h.inner.getMixDigest()
}

func (h *Header) Beneficiary() Address {
	return h.inner.getCoinbase()
}

func (h *Header) LogsBloom() Bloom {
	return h.inner.getLogsBloom()
}

func (h *Header) ExtraData() []byte {
	return h.inner.getExtraData()
}

func (h *Header) Difficulty() uint64 {
	return h.inner.getDifficulty()
}

func (h *Header) Number() uint64 {
	return h.inner.getNumber()
}

func (h *Header) GasLimit() uint64 {
	return h.inner.getGasLimit()
}

func (h *Header) GasUsed() uint64 {
	return h.inner.getGasUsed()
}

func (h *Header) Timestamp() int64 {
	return h.inner.getTimestamp()
}

func (h *Header) Nonce() uint64 {
	return h.inner.getNonce()
}

func (h *Header) BaseFeePerGas() *big.Int {
	return h.inner.getBaseFeePerGas()
}

func (h *Header) WithdrawalsRoot() Hash {
	return h.inner.getWithdrawalsRoot()
}

func (h *Header) BlobGasUsed() uint64 {
	return h.inner.getBlobGasUsed()
}

func (h *Header) ExcessBlobGas() uint64 {
	return h.inner.getExcessBlobGas()
}

func (h *Header) ParentBeaconBlockRoot() Hash {
	return h.inner.getParentBeaconBlockRoot()
}

func (h *Header) RequestsHash() Hash {
	return h.inner.getRequestsHash()
}

// ToProto converts the Header into its proto representation
func (h *Header) ToProto() (*ethProto.Header, error) {
	switch h.inner.getType() {
	case headerLegacy:
		header := h.inner.(*HeaderLegacy)

		return header.ToProto(), nil
	case headerEIP1559:
		header := h.inner.(*HeaderEIP1559)

		return header.ToProto(), nil
	case headerEIP4895:
		header := h.inner.(*HeaderEIP4895)

		return header.ToProto(), nil
	case headerEIP4844:
		header := h.inner.(*HeaderEIP4844)

		return header.ToProto(), nil
	case headerEIP7685:
		header := h.inner.(*HeaderEIP7685)

		return header.ToProto(), nil
	}

	return nil, fmt.Errorf("unknown header type, %x", h.inner.getType())
}

// FromProto converts a proto Header into a header
func (h *Header) FromProto(pb *ethProto.Header) error {
	if pb == nil {
		return ErrNilProtoHeader
	}

	switch pb.Payload.(type) {
	case *ethProto.Header_Eip1559:
		header := new(HeaderEIP1559)

		if err := header.FromProto(pb); err != nil {
			return fmt.Errorf("unable to parse EIP1559 header proto: %w", err)
		}

		h.inner = header
	case *ethProto.Header_Eip4895:
		header := new(HeaderEIP4895)

		if err := header.FromProto(pb); err != nil {
			return fmt.Errorf("unable to parse EIP4895 header proto: %w", err)
		}

		h.inner = header
	case *ethProto.Header_Eip4844:
		header := new(HeaderEIP4844)

		if err := header.FromProto(pb); err != nil {
			return fmt.Errorf("unable to parse EIP4844 header proto: %w", err)
		}

		h.inner = header
	case *ethProto.Header_Eip7685:
		header := new(HeaderEIP7685)

		if err := header.FromProto(pb); err != nil {
			return fmt.Errorf("unable to parse EIP7685 header proto: %w", err)
		}

		h.inner = header
	default:
		// Legacy header
		header := new(HeaderLegacy)

		if err := header.FromProto(pb); err != nil {
			return fmt.Errorf("unable to parse legacy header proto: %w", err)
		}

		h.inner = header
	}

	// Reset the cached hash, it belongs to the previous header
	h.hash = atomic.Value{}

	return nil
}
