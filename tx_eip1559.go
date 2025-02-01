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

	ErrInvalidProtoEIP1559Tx = errors.New("invalid proto EIP-1559 tx payload")
)

// TxEIP1559 represents a dynamic fee transaction,
// introduced as part of EIP-1559 (London hardfork)
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md
type TxEIP1559 struct {
	ChainID              *big.Int   // the ID of the chain
	MaxPriorityFeePerGas *big.Int   // the max priority fee per gas
	MaxFeePerGas         *big.Int   // the max fee per gas
	Value                *big.Int   // value of the transfer (if any)
	YParity, R, S        *big.Int   // the signature fields (y parity is {0, 1})
	To                   *Address   // recipient address (nil means contract deployment)
	Data                 []byte     // data (payload) of the tx, if any
	AccessList           AccessList // the allowed access list for the tx, if any
	Nonce                uint64     // the sender nonce
	Gas                  uint64     // the gas limit of the tx
}

func (tx *TxEIP1559) getType() byte {
	return Transaction1559
}

func (tx *TxEIP1559) getNonce() uint64 {
	return tx.Nonce
}

func (tx *TxEIP1559) getGas() uint64 {
	return tx.Gas
}

func (tx *TxEIP1559) getTo() *Address {
	return tx.To
}

func (tx *TxEIP1559) getValue() *big.Int {
	return tx.Value
}

func (tx *TxEIP1559) getChainID() *big.Int {
	return tx.ChainID
}

//nolint:nonamedreturns // Simpler this way
func (tx *TxEIP1559) getSigValues() (yParity, r, s *big.Int) {
	return tx.YParity, tx.R, tx.S
}

func (tx *TxEIP1559) getData() []byte {
	return tx.Data
}

func (tx *TxEIP1559) getGasPrice() *big.Int {
	return tx.MaxFeePerGas // return the max fee per gas
}

func (tx *TxEIP1559) getMaxFeePerGas() *big.Int {
	return tx.MaxFeePerGas
}

func (tx *TxEIP1559) getMaxPriorityFeePerGas() *big.Int {
	return tx.MaxPriorityFeePerGas
}

func (tx *TxEIP1559) getAccessList() AccessList {
	return tx.AccessList
}

func (tx *TxEIP1559) getHash() Hash {
	return BytesToHash(tx.SignaturePayload())
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
		address := BytesToAddress(to)

		tx.To = &address
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
		toAddress = tx.To.ToBytes()
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

// FromProto converts a proto Transaction (assumed to be EIP-1559) into a TxEIP1559
func (tx *TxEIP1559) FromProto(pb *txProto.Transaction) error {
	if pb == nil {
		return ErrNilProtoTx
	}

	// Check that the oneof payload is of type EIP1559
	eip1559Wrapper, ok := pb.Payload.(*txProto.Transaction_Eip1559)
	if !ok || eip1559Wrapper.Eip1559 == nil {
		return ErrInvalidProtoEIP1559Tx
	}

	tx.Nonce = pb.Nonce
	tx.Gas = pb.Gas
	tx.Data = pb.Data
	tx.Value = new(big.Int).SetBytes(pb.Value)
	// The YParity is stored in the 'v' field
	tx.YParity = new(big.Int).SetBytes(pb.V)
	tx.R = new(big.Int).SetBytes(pb.R)
	tx.S = new(big.Int).SetBytes(pb.S)

	tx.To = nil
	if len(pb.To) > 0 {
		addr := BytesToAddress(pb.To)

		tx.To = &addr
	}

	// Convert EIP-1559-specific fields
	eip := eip1559Wrapper.Eip1559

	tx.MaxPriorityFeePerGas = new(big.Int).SetBytes(eip.MaxPriorityFeePerGas)
	tx.MaxFeePerGas = new(big.Int).SetBytes(eip.MaxFeePerGas)
	tx.ChainID = new(big.Int).SetBytes(eip.ChainId)

	accessList := new(AccessList)
	accessList.FromProto(eip.AccessList)

	tx.AccessList = *accessList

	return nil
}

// ToProto converts the TxEIP1559 into its proto Transaction representation
func (tx *TxEIP1559) ToProto() (*txProto.Transaction, error) {
	pb := &txProto.Transaction{
		Nonce: tx.Nonce,
		Gas:   tx.Gas,
		Data:  tx.Data,
	}

	if tx.Value != nil {
		pb.Value = tx.Value.Bytes()
	}

	// The YParity is stored in the 'v' field
	if tx.YParity != nil {
		pb.V = tx.YParity.Bytes()
	}

	if tx.R != nil {
		pb.R = tx.R.Bytes()
	}

	if tx.S != nil {
		pb.S = tx.S.Bytes()
	}

	// Convert To address (empty means contract deployment)
	tx.To = nil
	if len(pb.To) > 0 {
		addr := BytesToAddress(pb.To)
		tx.To = &addr
	}

	// Set the EIP-1559 payload
	eip := &txProto.EIP1559{
		AccessList: tx.AccessList.ToProto(),
	}

	if tx.MaxPriorityFeePerGas != nil {
		eip.MaxPriorityFeePerGas = tx.MaxPriorityFeePerGas.Bytes()
	}

	if tx.MaxFeePerGas != nil {
		eip.MaxFeePerGas = tx.MaxFeePerGas.Bytes()
	}

	if tx.ChainID != nil {
		eip.ChainId = tx.ChainID.Bytes()
	}

	pb.Payload = &txProto.Transaction_Eip1559{
		Eip1559: eip,
	}

	return pb, nil
}
