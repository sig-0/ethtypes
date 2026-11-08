package ethtypes

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/keccak"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var ErrInvalidProtoEIP2930Tx = errors.New("invalid proto EIP-2930 tx payload")

var _ transactionData = (*TxEIP2930)(nil)

// TxEIP2930 represents an access list transaction,
// introduced as part of EIP-2930
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2930.md
type TxEIP2930 struct {
	ChainID       *big.Int   // the ID of the chain
	GasPrice      *big.Int   // the gas price of the tx
	Value         *big.Int   // value of the transfer (if any)
	YParity, R, S *big.Int   // the signature fields (y parity is {0, 1})
	To            *Address   // recipient address (nil means contract deployment)
	Data          []byte     // data (payload) of the tx, if any
	AccessList    AccessList // the allowed access list of the tx, if any
	Nonce         uint64     // the sender nonce
	Gas           uint64     // the gas limit of the tx
}

func (tx *TxEIP2930) getType() byte {
	return Transaction2930
}

func (tx *TxEIP2930) getNonce() uint64 {
	return tx.Nonce
}

func (tx *TxEIP2930) getGas() uint64 {
	return tx.Gas
}

func (tx *TxEIP2930) getTo() *Address {
	return tx.To
}

func (tx *TxEIP2930) getValue() *big.Int {
	return tx.Value
}

func (tx *TxEIP2930) getChainID() *big.Int {
	return tx.ChainID
}

//nolint:nonamedreturns // Simpler this way
func (tx *TxEIP2930) getSigValues() (yParity, r, s *big.Int) {
	return tx.YParity, tx.R, tx.S
}

func (tx *TxEIP2930) getData() []byte {
	return tx.Data
}

func (tx *TxEIP2930) getGasPrice() *big.Int {
	return tx.GasPrice
}

func (tx *TxEIP2930) getMaxFeePerGas() *big.Int {
	return tx.GasPrice
}

func (tx *TxEIP2930) getMaxPriorityFeePerGas() *big.Int {
	return tx.GasPrice
}

func (tx *TxEIP2930) getAccessList() AccessList {
	return tx.AccessList
}

func (tx *TxEIP2930) getMaxFeePerBlobGas() *big.Int {
	return nil
}

func (tx *TxEIP2930) getBlobVersionedHashes() []Hash {
	return nil
}

func (tx *TxEIP2930) getAuthorizationList() AuthorizationList {
	return nil
}

func (tx *TxEIP2930) getHash() Hash {
	return BytesToHash(tx.SignaturePayload())
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

	var d TxEIP2930

	// Decode the chain ID
	if listValues[0].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for chain ID, %s",
			listValues[0].GetType(),
		)
	}

	chainIDRaw, ok := listValues[0].GetValue().([]byte)
	if !ok || len(chainIDRaw) > 32 || (len(chainIDRaw) > 0 && chainIDRaw[0] == 0) {
		return ErrInvalidRLPChainID
	}

	d.ChainID = big.NewInt(0).SetBytes(chainIDRaw)

	// Decode the nonce
	if listValues[1].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for nonce, %s",
			listValues[1].GetType(),
		)
	}

	nonceRaw, ok := listValues[1].GetValue().([]byte)
	if !ok || len(nonceRaw) > 8 || (len(nonceRaw) > 0 && nonceRaw[0] == 0) {
		return ErrInvalidRLPNonce
	}

	d.Nonce = big.NewInt(0).SetBytes(nonceRaw).Uint64()

	// Decode the gas price
	if listValues[2].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for gas price, %s",
			listValues[2].GetType(),
		)
	}

	gasPriceRaw, ok := listValues[2].GetValue().([]byte)
	if !ok || len(gasPriceRaw) > 32 || (len(gasPriceRaw) > 0 && gasPriceRaw[0] == 0) {
		return ErrInvalidRLPGasPrice
	}

	d.GasPrice = big.NewInt(0).SetBytes(gasPriceRaw)

	// Decode the gas limit
	if listValues[3].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for gas limit, %s",
			listValues[3].GetType(),
		)
	}

	gasLimitRaw, ok := listValues[3].GetValue().([]byte)
	if !ok || len(gasLimitRaw) > 8 || (len(gasLimitRaw) > 0 && gasLimitRaw[0] == 0) {
		return ErrInvalidRLPGasLimit
	}

	d.Gas = big.NewInt(0).SetBytes(gasLimitRaw).Uint64()

	// Decode the recipient address (empty for a contract creation)
	if listValues[4].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for to address, %s",
			listValues[4].GetType(),
		)
	}

	toRaw, ok := listValues[4].GetValue().([]byte)
	if !ok || (len(toRaw) != 0 && len(toRaw) != addressSize) {
		return ErrInvalidRLPTo
	}

	if len(toRaw) != 0 {
		address := BytesToAddress(toRaw)

		d.To = &address
	}

	// Decode the value
	if listValues[5].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for value, %s",
			listValues[5].GetType(),
		)
	}

	valueRaw, ok := listValues[5].GetValue().([]byte)
	if !ok || len(valueRaw) > 32 || (len(valueRaw) > 0 && valueRaw[0] == 0) {
		return ErrInvalidRLPValue
	}

	d.Value = big.NewInt(0).SetBytes(valueRaw)

	// Decode the data
	if listValues[6].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for data, %s",
			listValues[6].GetType(),
		)
	}

	dataRaw, ok := listValues[6].GetValue().([]byte)
	if !ok || dataRaw == nil {
		return ErrInvalidRLPData
	}

	d.Data = dataRaw

	// Decode the access list
	if listValues[7].GetType() != ethrlp.List {
		return fmt.Errorf(
			"invalid RLP encoding type for access list, %s",
			listValues[7].GetType(),
		)
	}

	accessListRaw, ok := listValues[7].GetValue().([]ethrlp.Value)
	if !ok || accessListRaw == nil {
		return ErrInvalidRLPAccessList
	}

	if err = d.AccessList.FromRLPValues(accessListRaw); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRLPAccessList, err)
	}

	// Decode the v sig param
	if listValues[8].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for v sig param, %s",
			listValues[8].GetType(),
		)
	}

	yParityRaw, ok := listValues[8].GetValue().([]byte)
	if !ok || len(yParityRaw) > 32 || (len(yParityRaw) > 0 && yParityRaw[0] == 0) {
		return ErrInvalidRLPYParity
	}

	d.YParity = big.NewInt(0).SetBytes(yParityRaw)

	// Decode the r sig param
	if listValues[9].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for r sig param, %s",
			listValues[9].GetType(),
		)
	}

	rRaw, ok := listValues[9].GetValue().([]byte)
	if !ok || len(rRaw) > 32 || (len(rRaw) > 0 && rRaw[0] == 0) {
		return ErrInvalidRLPRParam
	}

	d.R = big.NewInt(0).SetBytes(rRaw)

	// Decode the s sig param
	if listValues[10].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for s sig param, %s",
			listValues[10].GetType(),
		)
	}

	sRaw, ok := listValues[10].GetValue().([]byte)
	if !ok || len(sRaw) > 32 || (len(sRaw) > 0 && sRaw[0] == 0) {
		return ErrInvalidRLPSParam
	}

	d.S = big.NewInt(0).SetBytes(sRaw)

	*tx = d

	return nil
}

// SignaturePayload constructs the EIP-2930 transaction signature payload.
// The signature payload (what's being signed) is the keccak of a specific RLP encoding.
//
// keccak256(0x01 || rlp([chainID, nonce, gasPrice, gas, to, value, data, accessList]))
func (tx *TxEIP2930) SignaturePayload() []byte {
	// Perform the RLP encoding of the tx
	rlpEncoding := tx.ToRLP()

	// Keccak the RLP encoding.
	// This keccak output is what's actually being
	// signed by the private key (this is the sign data)
	return keccak.New().Hash(rlpEncoding)
}

// FromProto converts a proto Transaction (assumed to be EIP-2930) into a TxEIP2930
func (tx *TxEIP2930) FromProto(pb *txProto.Transaction) error {
	if pb == nil {
		return ErrNilProtoTx
	}

	// Check that the oneof payload is of type EIP2930
	eip2930Wrapper, ok := pb.Payload.(*txProto.Transaction_Eip2930)
	if !ok || eip2930Wrapper.Eip2930 == nil {
		return ErrInvalidProtoEIP2930Tx
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

	// Convert EIP-2930-specific fields
	eip := eip2930Wrapper.Eip2930

	tx.GasPrice = new(big.Int).SetBytes(eip.GasPrice)
	tx.ChainID = new(big.Int).SetBytes(eip.ChainId)

	accessList := new(AccessList)
	accessList.FromProto(eip.AccessList)

	tx.AccessList = *accessList

	return nil
}

// ToProto converts the TxEIP2930 into its proto Transaction representation
func (tx *TxEIP2930) ToProto() *txProto.Transaction {
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

	if tx.To != nil {
		pb.To = tx.To.ToBytes()
	}

	// Set the EIP-2930 payload
	eip := &txProto.EIP2930{
		AccessList: tx.AccessList.ToProto(),
	}

	if tx.GasPrice != nil {
		eip.GasPrice = tx.GasPrice.Bytes()
	}

	if tx.ChainID != nil {
		eip.ChainId = tx.ChainID.Bytes()
	}

	pb.Payload = &txProto.Transaction_Eip2930{
		Eip2930: eip,
	}

	return pb
}

// ToRLP encodes the EIP-2930 transaction using RLP encoding.
//
// rlp([chainID, nonce, gasPrice, gas, to, value, data, accessList])
//
// 0x01 (transaction type) is appended as the first byte of the RLP encoding
func (tx *TxEIP2930) ToRLP() []byte {
	var toAddress []byte
	if tx.To != nil {
		toAddress = tx.To.ToBytes()
	}

	// Construct the RLP data
	rlpPayload := [][]byte{
		ethrlp.EncodeBytes(bigToBytes(tx.ChainID)),
		ethrlp.EncodeUint(tx.Nonce),
		ethrlp.EncodeBytes(bigToBytes(tx.GasPrice)),
		ethrlp.EncodeUint(tx.Gas),
		ethrlp.EncodeBytes(toAddress),
		ethrlp.EncodeBytes(bigToBytes(tx.Value)),
		ethrlp.EncodeBytes(tx.Data),
		tx.AccessList.ToRLP(),
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Concatenate the RLP encoding with the transaction type
	rlpEncoding = append([]byte{Transaction2930}, rlpEncoding...)

	return rlpEncoding
}

// ToSignedRLP encodes the signed EIP-2930 transaction using RLP encoding.
//
// rlp([chainID, nonce, gasPrice, gas, to, value, data, accessList, yParity, r, s])
//
// 0x01 (transaction type) is appended as the first byte of the RLP encoding
func (tx *TxEIP2930) ToSignedRLP() []byte {
	var toAddress []byte
	if tx.To != nil {
		toAddress = tx.To.ToBytes()
	}

	// Construct the RLP data
	rlpPayload := [][]byte{
		ethrlp.EncodeBytes(bigToBytes(tx.ChainID)),
		ethrlp.EncodeUint(tx.Nonce),
		ethrlp.EncodeBytes(bigToBytes(tx.GasPrice)),
		ethrlp.EncodeUint(tx.Gas),
		ethrlp.EncodeBytes(toAddress),
		ethrlp.EncodeBytes(bigToBytes(tx.Value)),
		ethrlp.EncodeBytes(tx.Data),
		tx.AccessList.ToRLP(),
		ethrlp.EncodeBytes(bigToBytes(tx.YParity)),
		ethrlp.EncodeBytes(bigToBytes(tx.R)),
		ethrlp.EncodeBytes(bigToBytes(tx.S)),
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Concatenate the RLP encoding with the transaction type
	rlpEncoding = append([]byte{Transaction2930}, rlpEncoding...)

	return rlpEncoding
}
