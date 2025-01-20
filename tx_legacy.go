package ethtypes

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/keccak"
	txProto "github.com/sig-0/ethtypes/proto/tx/v1"
)

var (
	ErrInvalidRLPNonce    = errors.New("invalid nonce RLP encoding")
	ErrInvalidRLPGasPrice = errors.New("invalid gas price RLP encoding")
	ErrInvalidRLPGasLimit = errors.New("invalid gas limit RLP encoding")
	ErrInvalidRLPValue    = errors.New("invalid value RLP encoding")
	ErrInvalidRLPData     = errors.New("invalid data RLP encoding")
	ErrInvalidRLPVParam   = errors.New("invalid v sig param RLP encoding")
	ErrInvalidRLPRParam   = errors.New("invalid r sig param RLP encoding")
	ErrInvalidRLPSParam   = errors.New("invalid s sig param RLP encoding")
)

// TxLegacy represents the legacy transaction type
// (pre EIP-2930, and pre EIP-1559)
type TxLegacy struct {
	GasPrice *big.Int // the gas price of the tx
	Value    *big.Int // value of the transfer (if any)
	V, R, S  *big.Int // the signature fields
	To       *[]byte  // recipient address (nil means contract deployment)
	Data     []byte   // data (payload) of the tx, if any
	Nonce    uint64   // the sender nonce
	Gas      uint64   // the gas limit of the tx
}

// FromRLP parses a legacy transaction from the transaction data RLP encoding.
// It expects the structure to be:
//
// [nonce, gasPrice, gas, to, value, data, v, r, s] (9 elements)
func (tx *TxLegacy) FromRLP(txPayload []byte) error {
	// Decode the RLP data
	list, err := ethrlp.DecodeBytes(txPayload)
	if err != nil {
		return fmt.Errorf("failed to decode transaction RLP data: %w", err)
	}

	if list.GetType() != ethrlp.List {
		return fmt.Errorf("invalid transaction RLP encoding type: %s", list.GetType())
	}

	// Extract the list RLP values (v, r, s are always the last on the input)
	listValues, _ := list.GetValue().([]ethrlp.Value)
	if len(listValues) != 9 {
		return fmt.Errorf(
			"invalid legacy transaction RLP encoding length: %d, expected %d",
			len(listValues),
			9,
		)
	}

	// Decode the nonce
	if listValues[0].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for nonce, %s",
			listValues[0].GetType(),
		)
	}

	nonceRaw, ok := listValues[0].GetValue().([]byte)
	if !ok || nonceRaw == nil {
		return ErrInvalidRLPNonce
	}

	tx.Nonce = big.NewInt(0).SetBytes(nonceRaw).Uint64()

	// Decode the gas price
	if listValues[1].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for gas price, %s",
			listValues[1].GetType(),
		)
	}

	gasPriceRaw, ok := listValues[1].GetValue().([]byte)
	if !ok || gasPriceRaw == nil {
		return ErrInvalidRLPGasPrice
	}

	tx.GasPrice = big.NewInt(0).SetBytes(gasPriceRaw)

	// Decode the gas limit
	if listValues[2].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for gas limit, %s",
			listValues[2].GetType(),
		)
	}

	gasLimitRaw, ok := listValues[2].GetValue().([]byte)
	if !ok || gasLimitRaw == nil {
		return ErrInvalidRLPGasLimit
	}

	tx.Gas = big.NewInt(0).SetBytes(gasLimitRaw).Uint64()

	// Decode the recipient address
	if listValues[3].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for to address, %s",
			listValues[3].GetType(),
		)
	}

	if toRaw := listValues[3].GetValue(); toRaw != nil {
		to, _ := toRaw.([]byte)
		tx.To = &to
	}

	// Decode the value
	if listValues[4].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for value, %s",
			listValues[4].GetType(),
		)
	}

	valueRaw, ok := listValues[4].GetValue().([]byte)
	if !ok || valueRaw == nil {
		return ErrInvalidRLPValue
	}

	tx.Value = big.NewInt(0).SetBytes(valueRaw)

	// Decode the data
	if listValues[5].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for data, %s",
			listValues[5].GetType(),
		)
	}

	dataRaw, ok := listValues[5].GetValue().([]byte)
	if !ok || dataRaw == nil {
		return ErrInvalidRLPData
	}

	tx.Data = dataRaw

	// Decode the v sig param
	if listValues[6].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for v sig param, %s",
			listValues[6].GetType(),
		)
	}

	vRaw, ok := listValues[6].GetValue().([]byte)
	if !ok || vRaw == nil {
		return ErrInvalidRLPVParam
	}

	tx.V = big.NewInt(0).SetBytes(vRaw)

	// Decode the r sig param
	if listValues[7].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for r sig param, %s",
			listValues[7].GetType(),
		)
	}

	rRaw, ok := listValues[7].GetValue().([]byte)
	if !ok || rRaw == nil {
		return ErrInvalidRLPRParam
	}

	tx.R = big.NewInt(0).SetBytes(rRaw)

	// Decode the s sig param
	if listValues[8].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for s sig param, %s",
			listValues[8].GetType(),
		)
	}

	sRaw, ok := listValues[8].GetValue().([]byte)
	if !ok || sRaw == nil {
		return ErrInvalidRLPSParam
	}

	tx.S = big.NewInt(0).SetBytes(sRaw)

	return nil
}

// Magic number values required for V sig param verification
var (
	big35 = big.NewInt(35)
	big2  = big.NewInt(2)
	big0  = big.NewInt(0)
)

// SignaturePayload constructs the legacy transaction signature payload.
// The signature payload (what's being signed) is the keccak of a specific RLP encoding.
//
// RLP structure that needs to be constructed and keccak-ed later:
//
// - Pre-EIP-155 (Homestead) RLP: [nonce, gasPrice, gas, to, value, data] (6 elements)
//
// - EIP-155 RLP: [nonce, gasPrice, gas, to, value, data, chainID, 0, 0] (9 elements)
func (tx *TxLegacy) SignaturePayload() []byte {
	// Check for EIP-155 (V >= 35).
	// If so, chainID = (V - 35) / 2 or (V - 36) / 2
	// (we just do int arithmetic to see if chainID > 0)
	chainID := big.NewInt(0).Sub(tx.V, big35)
	chainID.Div(chainID, big2) // this is floor((V-35)/2)

	var rlpPayload [][]byte

	var toAddress []byte
	if tx.To != nil {
		toAddress = *tx.To
	}

	// Check how the signing data should be constructed
	if tx.V.Cmp(big35) >= 0 && chainID.Sign() > 0 {
		// EIP-155 path
		// We need to RLP 9 elements
		rlpPayload = [][]byte{
			ethrlp.EncodeUint(tx.Nonce),
			ethrlp.EncodeBigInt(tx.GasPrice),
			ethrlp.EncodeUint(tx.Gas),
			ethrlp.EncodeBytes(toAddress),
			ethrlp.EncodeBigInt(tx.Value),
			ethrlp.EncodeBytes(tx.Data),
			ethrlp.EncodeBigInt(chainID),
			ethrlp.EncodeBigInt(big0),
			ethrlp.EncodeBigInt(big0),
		}
	} else {
		// Legacy, pre-EIP-155 path
		// We need to RLP 6 elements
		rlpPayload = [][]byte{
			ethrlp.EncodeUint(tx.Nonce),
			ethrlp.EncodeBigInt(tx.GasPrice),
			ethrlp.EncodeUint(tx.Gas),
			ethrlp.EncodeBytes(toAddress),
			ethrlp.EncodeBigInt(tx.Value),
			ethrlp.EncodeBytes(tx.Data),
		}
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Keccak the RLP encoding.
	// This keccak output is what's actually being
	// signed by the private key (this is the sign data)
	return keccak.New().Hash(rlpEncoding)
}

// ToProto converts a legacy transaction to the proto format
func (tx *TxLegacy) ToProto() *txProto.TransactionLegacy {
	protoTx := &txProto.TransactionLegacy{
		TransactionCommon: &txProto.TransactionCommon{
			Nonce: tx.Nonce,
			Gas:   tx.Gas,
			Value: tx.Value.Bytes(),
			Data:  tx.Data,
			V:     tx.V.Bytes(),
			R:     tx.R.Bytes(),
			S:     tx.S.Bytes(),
		},
		GasPrice: tx.GasPrice.Bytes(),
	}

	// Check if the recipient address is set.
	// If not, it means the transaction is a contract deployment
	if tx.To != nil {
		protoTx.TransactionCommon.To = *tx.To
	}

	return protoTx
}

// FromProto converts the legacy tx proto format to a legacy transaction
func (tx *TxLegacy) FromProto(protoTx *txProto.TransactionLegacy) {
	tx.Nonce = protoTx.TransactionCommon.GetNonce()
	tx.Gas = protoTx.TransactionCommon.GetGas()
	tx.Value = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetValue())
	tx.Data = protoTx.TransactionCommon.GetData()
	tx.V = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetV())
	tx.R = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetR())
	tx.S = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetS())
	tx.GasPrice = big.NewInt(0).SetBytes(protoTx.GetGasPrice())

	to := protoTx.TransactionCommon.GetTo()
	if to != nil {
		tx.To = &to
	}
}
