package ethtypes

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/keccak"
	txProto "github.com/sig-0/ethtypes/proto/tx/v1"
)

// TxEIP2930 represents an access list transaction,
// introduced as part of EIP-2930
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2930.md
type TxEIP2930 struct {
	ChainID    *big.Int   // the ID of the chain
	GasPrice   *big.Int   // the gas price of the tx
	Value      *big.Int   // value of the transfer (if any)
	V, R, S    *big.Int   // the signature fields
	To         *[]byte    // recipient address (nil means contract deployment)
	Data       []byte     // data (payload) of the tx, if any
	AccessList AccessList // the allowed access list of the tx, if any
	Nonce      uint64     // the sender nonce
	Gas        uint64     // the gas limit of the tx
}

// FromRLP parses an EIP-2930 transaction from the transaction data RLP encoding.
// It expects the structure to be:
//
// [chainID, nonce, gasPrice, gas, to, value, data, accessList, yParity, r, s] (11 elements)
func (tx *TxEIP2930) FromRLP(txData []byte) error {
	// Decode the RLP data
	list, err := ethrlp.DecodeBytes(txData)
	if err != nil {
		return fmt.Errorf("failed to decode transaction RLP data: %w", err)
	}

	if list.GetType() != ethrlp.List {
		return fmt.Errorf("invalid transaction RLP encoding type: %s", list.GetType())
	}

	// Extract the list RLP values (v, r, s are always the last on the input)
	listValues, _ := list.GetValue().([]ethrlp.Value)
	if len(listValues) != 11 {
		return fmt.Errorf(
			"invalid EIP-2930 transaction RLP encoding length: %d, expected %d",
			len(listValues),
			11,
		)
	}

	// Decode the chain ID
	if listValues[0].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for chain ID, %s",
			listValues[0].GetType(),
		)
	}

	chainIDRaw, ok := listValues[0].GetValue().([]byte)
	if !ok || chainIDRaw == nil {
		return errors.New("invalid chain ID RLP encoding")
	}

	tx.ChainID = big.NewInt(0).SetBytes(chainIDRaw)

	// Decode the nonce
	if listValues[1].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for nonce, %s",
			listValues[0].GetType(),
		)
	}

	nonceRaw, ok := listValues[1].GetValue().([]byte)
	if !ok || nonceRaw == nil {
		return errors.New("invalid nonce RLP encoding")
	}

	tx.Nonce = big.NewInt(0).SetBytes(nonceRaw).Uint64()

	// Decode the max priority fee per gas
	if listValues[2].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for max priority fee per gas, %s",
			listValues[2].GetType(),
		)
	}

	gasPriceRaw, ok := listValues[2].GetValue().([]byte)
	if !ok || gasPriceRaw == nil {
		return errors.New("invalid gas price RLP encoding")
	}

	tx.GasPrice = big.NewInt(0).SetBytes(gasPriceRaw)

	// Decode the gas limit
	if listValues[3].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for gas limit, %s",
			listValues[3].GetType(),
		)
	}

	gasLimitRaw, ok := listValues[3].GetValue().([]byte)
	if !ok || gasLimitRaw == nil {
		return errors.New("invalid gas limit RLP encoding")
	}

	tx.Gas = big.NewInt(0).SetBytes(gasLimitRaw).Uint64()

	// Decode the recipient address
	if listValues[4].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for to address, %s",
			listValues[4].GetType(),
		)
	}

	if toRaw := listValues[4].GetValue(); toRaw != nil {
		to, _ := toRaw.([]byte)
		tx.To = &to
	}

	// Decode the value
	if listValues[5].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for value, %s",
			listValues[5].GetType(),
		)
	}

	valueRaw, ok := listValues[5].GetValue().([]byte)
	if !ok || valueRaw == nil {
		return errors.New("invalid value RLP encoding")
	}

	tx.Value = big.NewInt(0).SetBytes(valueRaw)

	// Decode the data
	if listValues[6].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for data, %s",
			listValues[6].GetType(),
		)
	}

	dataRaw, ok := listValues[6].GetValue().([]byte)
	if !ok || dataRaw == nil {
		return errors.New("invalid data RLP encoding")
	}

	tx.Data = dataRaw

	// Decode the access list
	var accessList AccessList

	if listValues[7].GetType() != ethrlp.List {
		return fmt.Errorf(
			"invalid RLP encoding type for access list, %s",
			listValues[7].GetType(),
		)
	}

	accessListRaw, ok := listValues[7].GetValue().([]ethrlp.Value)
	if !ok || accessListRaw == nil {
		return errors.New("invalid access list RLP encoding")
	}

	accessList = make(AccessList, 0)
	if err = accessList.FromRLPValues(accessListRaw); err != nil {
		return fmt.Errorf("invalid access list RLP encoding: %w", err)
	}

	tx.AccessList = accessList

	// Decode the v sig param
	if listValues[8].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for v sig param, %s",
			listValues[9].GetType(),
		)
	}

	vRaw, ok := listValues[8].GetValue().([]byte)
	if !ok || vRaw == nil {
		return errors.New("invalid v sig param RLP encoding")
	}

	tx.V = big.NewInt(0).SetBytes(vRaw)

	// Decode the r sig param
	if listValues[9].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for r sig param, %s",
			listValues[9].GetType(),
		)
	}

	rRaw, ok := listValues[9].GetValue().([]byte)
	if !ok || rRaw == nil {
		return errors.New("invalid r sig param RLP encoding")
	}

	tx.R = big.NewInt(0).SetBytes(rRaw)

	// Decode the s sig param
	if listValues[10].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for s sig param, %s",
			listValues[10].GetType(),
		)
	}

	sRaw, ok := listValues[10].GetValue().([]byte)
	if !ok || sRaw == nil {
		return errors.New("invalid r sig param RLP encoding")
	}

	tx.S = big.NewInt(0).SetBytes(sRaw)

	return nil
}

// SignaturePayload constructs the EIP-2930 transaction signature payload.
// The signature payload (what's being signed) is the keccak of a specific RLP encoding.
//
// RLP structure that needs to be constructed and keccak-ed later:
// rlp([chainID, nonce, gasPrice, gas, to, value, data, accessList])
//
// The type of tx needs to be appended before keccaking (in this case 0x01, for EIP-2930 txs):
//
// keccak256(0x01 || rlp([chainID, nonce, gasPrice, gas, to, value, data, accessList]))
func (tx *TxEIP2930) SignaturePayload() []byte {
	var rlpPayload [][]byte

	var toAddress []byte
	if tx.To != nil {
		toAddress = *tx.To
	}

	// Encode the access list
	accessListEnc := new(AccessList).ToRLP()

	if len(tx.AccessList) != 0 {
		accessListEnc = tx.AccessList.ToRLP()
	}

	rlpPayload = [][]byte{
		ethrlp.EncodeBigInt(tx.ChainID),
		ethrlp.EncodeUint(tx.Nonce),
		ethrlp.EncodeBigInt(tx.GasPrice),
		ethrlp.EncodeUint(tx.Gas),
		ethrlp.EncodeBytes(toAddress),
		ethrlp.EncodeBigInt(tx.Value),
		ethrlp.EncodeBytes(tx.Data),
		accessListEnc,
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Concatenate the RLP encoding with the transaction type
	rlpEncoding = append([]byte{Transaction2930}, rlpEncoding...)

	// Keccak the RLP encoding.
	// This keccak output is what's actually being
	// signed by the private key (this is the sign data)
	return keccak.New().Hash(rlpEncoding)
}

// ToProto converts an EIP-2930 transaction to the proto format
func (tx *TxEIP2930) ToProto() *txProto.Transaction2930 {
	protoTx := &txProto.Transaction2930{
		TransactionCommon: &txProto.TransactionCommon{
			Nonce: tx.Nonce,
			Gas:   tx.Gas,
			Value: tx.Value.Bytes(),
			Data:  tx.Data,
			V:     tx.V.Bytes(),
			R:     tx.R.Bytes(),
			S:     tx.S.Bytes(),
		},
		Type:       Transaction1559,
		GasPrice:   tx.GasPrice.Bytes(),
		AccessList: tx.AccessList.ToProto(),
	}

	// Check if the recipient address is set.
	// If not, it means the transaction is a contract deployment
	if tx.To != nil {
		protoTx.TransactionCommon.To = *tx.To
	}

	return protoTx
}

// FromProto converts the EIP-2930 tx proto format to an EIP-1559 transaction
func (tx *TxEIP2930) FromProto(protoTx *txProto.Transaction2930) {
	tx.Nonce = protoTx.TransactionCommon.GetNonce()
	tx.Gas = protoTx.TransactionCommon.GetGas()
	tx.Value = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetValue())
	tx.Data = protoTx.TransactionCommon.GetData()
	tx.V = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetV())
	tx.R = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetR())
	tx.S = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetS())
	tx.GasPrice = big.NewInt(0).SetBytes(protoTx.GetGasPrice())

	accessList := make(AccessList, 0, len(protoTx.AccessList))
	accessList.FromProto(protoTx.AccessList)

	tx.AccessList = accessList

	to := protoTx.TransactionCommon.GetTo()
	if to != nil {
		tx.To = &to
	}
}
