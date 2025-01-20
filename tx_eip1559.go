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
	ErrInvalidRLPChainID        = errors.New("invalid chain ID RLP encoding")
	ErrInvalidRLPMaxPriorityFee = errors.New("invalid max priority fee per gas RLP encoding")
	ErrInvalidRLPMaxFeePerGas   = errors.New("invalid max fee per gas RLP encoding")
	ErrInvalidRLPAccessList     = errors.New("invalid access list RLP encoding")
	ErrInvalidRLPYParity        = errors.New("invalid y parity param RLP encoding")
)

// TxEIP1559 represents a dynamic fee transaction,
// introduced as part of EIP-1559 (London hardfork)
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md
type TxEIP1559 struct {
	ChainID              *big.Int   // the ID of the chain
	Nonce                uint64     // the sender nonce
	MaxPriorityFeePerGas *big.Int   // the max priority fee per gas
	MaxFeePerGas         *big.Int   // the max fee per gas
	Gas                  uint64     // the gas limit of the tx
	To                   *[]byte    // recipient address (nil means contract deployment)
	Value                *big.Int   // value of the transfer (if any)
	Data                 []byte     // data (payload) of the tx, if any
	AccessList           AccessList // the allowed access list for the tx, if any
	YParity, R, S        *big.Int   // the signature fields
}

// FromRLP parses an EIP-1559 transaction from the transaction data RLP encoding.
// It expects the structure to be:
//
// [chainID, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList, yParity, r, s] (12 elements)
func (tx *TxEIP1559) FromRLP(txData []byte) error {
	// Decode the RLP data
	list, err := ethrlp.DecodeBytes(txData)
	if err != nil {
		return fmt.Errorf("failed to decode transaction RLP data: %w", err)
	}

	if list.GetType() != ethrlp.List {
		return fmt.Errorf("invalid transaction RLP encoding type: %s", list.GetType())
	}

	// Extract the list RLP values (yParity, r, s are always the last on the input)
	listValues, _ := list.GetValue().([]ethrlp.Value)
	if len(listValues) != 12 {
		return fmt.Errorf(
			"invalid legacy transaction RLP encoding length: %d, expected %d",
			len(listValues),
			12,
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
		return ErrInvalidRLPChainID
	}

	tx.ChainID = big.NewInt(0).SetBytes(chainIDRaw)

	// Decode the nonce
	if listValues[1].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for nonce, %s",
			listValues[1].GetType(),
		)
	}

	nonceRaw, ok := listValues[1].GetValue().([]byte)
	if !ok || nonceRaw == nil {
		return ErrInvalidRLPNonce
	}

	tx.Nonce = big.NewInt(0).SetBytes(nonceRaw).Uint64()

	// Decode the max priority fee per gas
	if listValues[2].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for max priority fee per gas, %s",
			listValues[2].GetType(),
		)
	}

	maxPriorityFeePerGasRaw, ok := listValues[2].GetValue().([]byte)
	if !ok || maxPriorityFeePerGasRaw == nil {
		return ErrInvalidRLPMaxPriorityFee
	}

	tx.MaxPriorityFeePerGas = big.NewInt(0).SetBytes(maxPriorityFeePerGasRaw)

	// Decode the max fee per gas
	if listValues[3].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for max fee per gas, %s",
			listValues[3].GetType(),
		)
	}

	maxFeePerGasRaw, ok := listValues[3].GetValue().([]byte)
	if !ok || maxFeePerGasRaw == nil {
		return ErrInvalidRLPMaxFeePerGas
	}

	tx.MaxFeePerGas = big.NewInt(0).SetBytes(maxFeePerGasRaw)

	// Decode the gas limit
	if listValues[4].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for gas limit, %s",
			listValues[4].GetType(),
		)
	}

	gasLimitRaw, ok := listValues[4].GetValue().([]byte)
	if !ok || gasLimitRaw == nil {
		return ErrInvalidRLPGasLimit
	}

	tx.Gas = big.NewInt(0).SetBytes(gasLimitRaw).Uint64()

	// Decode the recipient address
	if listValues[5].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for to address, %s",
			listValues[5].GetType(),
		)
	}

	if toRaw := listValues[5].GetValue(); toRaw != nil {
		to, _ := toRaw.([]byte)
		tx.To = &to
	}

	// Decode the value
	if listValues[6].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for value, %s",
			listValues[6].GetType(),
		)
	}

	valueRaw, ok := listValues[6].GetValue().([]byte)
	if !ok || valueRaw == nil {
		return ErrInvalidRLPValue
	}

	tx.Value = big.NewInt(0).SetBytes(valueRaw)

	// Decode the data
	if listValues[7].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for data, %s",
			listValues[7].GetType(),
		)
	}

	dataRaw, ok := listValues[7].GetValue().([]byte)
	if !ok || dataRaw == nil {
		return ErrInvalidRLPData
	}

	tx.Data = dataRaw

	// Decode the access list
	var accessList AccessList

	if listValues[8].GetType() != ethrlp.List {
		return fmt.Errorf(
			"invalid RLP encoding type for access list, %s",
			listValues[8].GetType(),
		)
	}

	accessListRaw, ok := listValues[8].GetValue().([]ethrlp.Value)
	if !ok || accessListRaw == nil {
		return ErrInvalidRLPAccessList
	}

	accessList = make(AccessList, 0)
	if err = accessList.FromRLPValues(accessListRaw); err != nil {
		return fmt.Errorf("invalid access list RLP encoding: %w", err)
	}

	tx.AccessList = accessList

	// Decode the v sig param
	if listValues[9].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for v sig param, %s",
			listValues[9].GetType(),
		)
	}

	yParityRaw, ok := listValues[9].GetValue().([]byte)
	if !ok || yParityRaw == nil {
		return ErrInvalidRLPYParity
	}

	tx.YParity = big.NewInt(0).SetBytes(yParityRaw)

	// Decode the r sig param
	if listValues[10].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for r sig param, %s",
			listValues[10].GetType(),
		)
	}

	rRaw, ok := listValues[10].GetValue().([]byte)
	if !ok || rRaw == nil {
		return ErrInvalidRLPRParam
	}

	tx.R = big.NewInt(0).SetBytes(rRaw)

	// Decode the s sig param
	if listValues[11].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for s sig param, %s",
			listValues[11].GetType(),
		)
	}

	sRaw, ok := listValues[11].GetValue().([]byte)
	if !ok || sRaw == nil {
		return ErrInvalidRLPSParam
	}

	tx.S = big.NewInt(0).SetBytes(sRaw)

	return nil
}

// SignaturePayload constructs the EIP-1559 transaction signature payload.
// The signature payload (what's being signed) is the keccak of a specific RLP encoding.
//
// RLP structure that needs to be constructed and keccak-ed later:
// rlp([chainID, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])
//
// The type of tx needs to be appended before keccaking (in this case 0x02, for EIP-1559 txs):
//
// keccak256(0x02 || rlp([chainID, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]))
func (tx *TxEIP1559) SignaturePayload() []byte {
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
		ethrlp.EncodeBigInt(tx.MaxPriorityFeePerGas),
		ethrlp.EncodeBigInt(tx.MaxFeePerGas),
		ethrlp.EncodeUint(tx.Gas),
		ethrlp.EncodeBytes(toAddress),
		ethrlp.EncodeBigInt(tx.Value),
		ethrlp.EncodeBytes(tx.Data),
		accessListEnc,
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Concatenate the RLP encoding with the transaction type
	rlpEncoding = append([]byte{Transaction1559}, rlpEncoding...)

	// Keccak the RLP encoding.
	// This keccak output is what's actually being
	// signed by the private key (this is the sign data)
	return keccak.New().Hash(rlpEncoding)
}

// ToProto converts an EIP-1559 transaction to the proto format
func (tx *TxEIP1559) ToProto() *txProto.Transaction1559 {
	protoTx := &txProto.Transaction1559{
		TransactionCommon: &txProto.TransactionCommon{
			Nonce: tx.Nonce,
			Gas:   tx.Gas,
			Value: tx.Value.Bytes(),
			Data:  tx.Data,
			V:     tx.YParity.Bytes(),
			R:     tx.R.Bytes(),
			S:     tx.S.Bytes(),
		},
		Type:                 Transaction1559,
		MaxPriorityFeePerGas: tx.MaxPriorityFeePerGas.Bytes(),
		MaxFeePerGas:         tx.MaxFeePerGas.Bytes(),
		AccessList:           tx.AccessList.ToProto(),
	}

	// Check if the recipient address is set.
	// If not, it means the transaction is a contract deployment
	if tx.To != nil {
		protoTx.TransactionCommon.To = *tx.To
	}

	return protoTx
}

// FromProto converts the EIP-1559 tx proto format to an EIP-1559 transaction
func (tx *TxEIP1559) FromProto(protoTx *txProto.Transaction1559) {
	tx.Nonce = protoTx.TransactionCommon.GetNonce()
	tx.Gas = protoTx.TransactionCommon.GetGas()
	tx.Value = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetValue())
	tx.Data = protoTx.TransactionCommon.GetData()
	tx.YParity = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetV())
	tx.R = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetR())
	tx.S = big.NewInt(0).SetBytes(protoTx.TransactionCommon.GetS())
	tx.MaxPriorityFeePerGas = big.NewInt(0).SetBytes(protoTx.GetMaxPriorityFeePerGas())
	tx.MaxFeePerGas = big.NewInt(0).SetBytes(protoTx.GetMaxFeePerGas())

	accessList := make(AccessList, 0, len(protoTx.AccessList))
	accessList.FromProto(protoTx.AccessList)

	tx.AccessList = accessList

	to := protoTx.TransactionCommon.GetTo()
	if to != nil {
		tx.To = &to
	}

	return
}
