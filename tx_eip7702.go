package ethtypes

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/sig-0/ethrlp"
	"github.com/sig-0/ethtypes/keccak"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var (
	ErrInvalidRLPAuthorizationList = errors.New("invalid authorization list RLP encoding")

	ErrInvalidProtoEIP7702Tx = errors.New("invalid proto EIP-7702 tx payload")
)

var _ transactionData = (*TxEIP7702)(nil)

// TxEIP7702 represents a set-code transaction,
// introduced as part of EIP-7702 (Prague hardfork)
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7702.md
type TxEIP7702 struct {
	ChainID              *big.Int          // the ID of the chain
	MaxPriorityFeePerGas *big.Int          // the max priority fee per gas
	MaxFeePerGas         *big.Int          // the max fee per gas
	Value                *big.Int          // value of the transfer (if any)
	YParity, R, S        *big.Int          // the signature fields (y parity is {0, 1})
	Data                 []byte            // data (payload) of the tx, if any
	AccessList           AccessList        // the allowed access list for the tx, if any
	AuthorizationList    AuthorizationList // the authorization list of the tx
	To                   Address           // recipient address (contract deployment is not allowed)
	Nonce                uint64            // the sender nonce
	Gas                  uint64            // the gas limit of the tx
}

func (tx *TxEIP7702) getType() byte {
	return Transaction7702
}

func (tx *TxEIP7702) getNonce() uint64 {
	return tx.Nonce
}

func (tx *TxEIP7702) getGas() uint64 {
	return tx.Gas
}

func (tx *TxEIP7702) getTo() *Address {
	return &tx.To
}

func (tx *TxEIP7702) getValue() *big.Int {
	return tx.Value
}

func (tx *TxEIP7702) getChainID() *big.Int {
	return tx.ChainID
}

//nolint:nonamedreturns // Simpler this way
func (tx *TxEIP7702) getSigValues() (yParity, r, s *big.Int) {
	return tx.YParity, tx.R, tx.S
}

func (tx *TxEIP7702) getData() []byte {
	return tx.Data
}

func (tx *TxEIP7702) getGasPrice() *big.Int {
	return tx.MaxFeePerGas // return the max fee per gas
}

func (tx *TxEIP7702) getMaxFeePerGas() *big.Int {
	return tx.MaxFeePerGas
}

func (tx *TxEIP7702) getMaxPriorityFeePerGas() *big.Int {
	return tx.MaxPriorityFeePerGas
}

func (tx *TxEIP7702) getAccessList() AccessList {
	return tx.AccessList
}

func (tx *TxEIP7702) getMaxFeePerBlobGas() *big.Int {
	return nil
}

func (tx *TxEIP7702) getBlobVersionedHashes() []Hash {
	return nil
}

func (tx *TxEIP7702) getAuthorizationList() AuthorizationList {
	return tx.AuthorizationList
}

func (tx *TxEIP7702) getHash() Hash {
	return BytesToHash(tx.SignaturePayload())
}

// SignaturePayload constructs the EIP-7702 transaction signature payload.
// The signature payload (what's being signed) is the keccak of a specific RLP encoding.
//
// keccak256(0x04 || rlp([chainID, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList,
// authorizationList]))
func (tx *TxEIP7702) SignaturePayload() []byte {
	return keccak.New().Hash(tx.ToRLP())
}

// ToRLP encodes the EIP-7702 transaction using RLP encoding.
//
// rlp([chainID, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList,
// authorizationList])
//
// 0x04 (transaction type) is appended as the first byte of the RLP encoding
func (tx *TxEIP7702) ToRLP() []byte {
	// Construct the RLP data
	rlpPayload := [][]byte{
		ethrlp.EncodeBytes(bigToBytes(tx.ChainID)),
		ethrlp.EncodeUint(tx.Nonce),
		ethrlp.EncodeBytes(bigToBytes(tx.MaxPriorityFeePerGas)),
		ethrlp.EncodeBytes(bigToBytes(tx.MaxFeePerGas)),
		ethrlp.EncodeUint(tx.Gas),
		ethrlp.EncodeBytes(tx.To.ToBytes()),
		ethrlp.EncodeBytes(bigToBytes(tx.Value)),
		ethrlp.EncodeBytes(tx.Data),
		tx.AccessList.ToRLP(),
		tx.AuthorizationList.toRLP(),
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Concatenate the RLP encoding with the transaction type
	rlpEncoding = append([]byte{Transaction7702}, rlpEncoding...)

	return rlpEncoding
}

// ToSignedRLP encodes the signed EIP-7702 transaction using RLP encoding.
//
// rlp([chainID, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList,
// authorizationList, yParity, r, s])
//
// 0x04 (transaction type) is appended as the first byte of the RLP encoding
func (tx *TxEIP7702) ToSignedRLP() []byte {
	// Construct the RLP data
	rlpPayload := [][]byte{
		ethrlp.EncodeBytes(bigToBytes(tx.ChainID)),
		ethrlp.EncodeUint(tx.Nonce),
		ethrlp.EncodeBytes(bigToBytes(tx.MaxPriorityFeePerGas)),
		ethrlp.EncodeBytes(bigToBytes(tx.MaxFeePerGas)),
		ethrlp.EncodeUint(tx.Gas),
		ethrlp.EncodeBytes(tx.To.ToBytes()),
		ethrlp.EncodeBytes(bigToBytes(tx.Value)),
		ethrlp.EncodeBytes(tx.Data),
		tx.AccessList.ToRLP(),
		tx.AuthorizationList.toRLP(),
		ethrlp.EncodeBytes(bigToBytes(tx.YParity)),
		ethrlp.EncodeBytes(bigToBytes(tx.R)),
		ethrlp.EncodeBytes(bigToBytes(tx.S)),
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	// Concatenate the RLP encoding with the transaction type
	rlpEncoding = append([]byte{Transaction7702}, rlpEncoding...)

	return rlpEncoding
}

// FromRLP parses an EIP-7702 transaction from the transaction data RLP encoding.
// It expects the structure to be:
//
// [chainID, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList,
// authorizationList, yParity, r, s] (13 elements)
func (tx *TxEIP7702) FromRLP(payload []byte) error {
	// Decode the RLP data
	list, err := ethrlp.DecodeBytes(payload)
	if err != nil {
		return fmt.Errorf("failed to decode transaction RLP data: %w", err)
	}

	if list.GetType() != ethrlp.List {
		return fmt.Errorf("invalid transaction RLP encoding type: %s", list.GetType())
	}

	// Extract the list RLP values (yParity, r, s are always the last on the input)
	listValues, _ := list.GetValue().([]ethrlp.Value)
	if len(listValues) != 13 {
		return fmt.Errorf(
			"invalid EIP-7702 transaction RLP encoding length: %d, expected %d",
			len(listValues),
			13,
		)
	}

	var d TxEIP7702

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

	// Decode the max priority fee per gas
	if listValues[2].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for max priority fee per gas, %s",
			listValues[2].GetType(),
		)
	}

	maxPriorityFeePerGasRaw, ok := listValues[2].GetValue().([]byte)
	if !ok || len(maxPriorityFeePerGasRaw) > 32 || (len(maxPriorityFeePerGasRaw) > 0 && maxPriorityFeePerGasRaw[0] == 0) {
		return ErrInvalidRLPMaxPriorityFee
	}

	d.MaxPriorityFeePerGas = big.NewInt(0).SetBytes(maxPriorityFeePerGasRaw)

	// Decode the max fee per gas
	if listValues[3].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for max fee per gas, %s",
			listValues[3].GetType(),
		)
	}

	maxFeePerGasRaw, ok := listValues[3].GetValue().([]byte)
	if !ok || len(maxFeePerGasRaw) > 32 || (len(maxFeePerGasRaw) > 0 && maxFeePerGasRaw[0] == 0) {
		return ErrInvalidRLPMaxFeePerGas
	}

	d.MaxFeePerGas = big.NewInt(0).SetBytes(maxFeePerGasRaw)

	// Decode the gas limit
	if listValues[4].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for gas limit, %s",
			listValues[4].GetType(),
		)
	}

	gasLimitRaw, ok := listValues[4].GetValue().([]byte)
	if !ok || len(gasLimitRaw) > 8 || (len(gasLimitRaw) > 0 && gasLimitRaw[0] == 0) {
		return ErrInvalidRLPGasLimit
	}

	d.Gas = big.NewInt(0).SetBytes(gasLimitRaw).Uint64()

	// Decode the recipient address
	if listValues[5].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for to address, %s",
			listValues[5].GetType(),
		)
	}

	toRaw, ok := listValues[5].GetValue().([]byte)
	if !ok || len(toRaw) != addressSize {
		return ErrInvalidRLPTo
	}

	d.To = BytesToAddress(toRaw)

	// Decode the value
	if listValues[6].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for value, %s",
			listValues[6].GetType(),
		)
	}

	valueRaw, ok := listValues[6].GetValue().([]byte)
	if !ok || len(valueRaw) > 32 || (len(valueRaw) > 0 && valueRaw[0] == 0) {
		return ErrInvalidRLPValue
	}

	d.Value = big.NewInt(0).SetBytes(valueRaw)

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

	d.Data = dataRaw

	// Decode the access list
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

	if err = d.AccessList.FromRLPValues(accessListRaw); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRLPAccessList, err)
	}

	// Decode the authorization list
	if listValues[9].GetType() != ethrlp.List {
		return fmt.Errorf(
			"invalid RLP encoding type for authorization list, %s",
			listValues[9].GetType(),
		)
	}

	authorizationListRaw, ok := listValues[9].GetValue().([]ethrlp.Value)
	if !ok || authorizationListRaw == nil {
		return ErrInvalidRLPAuthorizationList
	}

	d.AuthorizationList = make(AuthorizationList, 0, len(authorizationListRaw))

	for i, authorizationRaw := range authorizationListRaw {
		if authorizationRaw.GetType() != ethrlp.List {
			return fmt.Errorf(
				"%w: invalid RLP encoding type for authorization %d, %s",
				ErrInvalidRLPAuthorizationList,
				i,
				authorizationRaw.GetType(),
			)
		}

		authorizationValues, _ := authorizationRaw.GetValue().([]ethrlp.Value)

		var authorization Authorization
		if err = authorization.fromRLPValues(authorizationValues); err != nil {
			return fmt.Errorf("%w: authorization %d: %w", ErrInvalidRLPAuthorizationList, i, err)
		}

		d.AuthorizationList = append(d.AuthorizationList, authorization)
	}

	// Decode the v sig param
	if listValues[10].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for v sig param, %s",
			listValues[10].GetType(),
		)
	}

	yParityRaw, ok := listValues[10].GetValue().([]byte)
	if !ok || len(yParityRaw) > 32 || (len(yParityRaw) > 0 && yParityRaw[0] == 0) {
		return ErrInvalidRLPYParity
	}

	d.YParity = big.NewInt(0).SetBytes(yParityRaw)

	// Decode the r sig param
	if listValues[11].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for r sig param, %s",
			listValues[11].GetType(),
		)
	}

	rRaw, ok := listValues[11].GetValue().([]byte)
	if !ok || len(rRaw) > 32 || (len(rRaw) > 0 && rRaw[0] == 0) {
		return ErrInvalidRLPRParam
	}

	d.R = big.NewInt(0).SetBytes(rRaw)

	// Decode the s sig param
	if listValues[12].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for s sig param, %s",
			listValues[12].GetType(),
		)
	}

	sRaw, ok := listValues[12].GetValue().([]byte)
	if !ok || len(sRaw) > 32 || (len(sRaw) > 0 && sRaw[0] == 0) {
		return ErrInvalidRLPSParam
	}

	d.S = big.NewInt(0).SetBytes(sRaw)

	*tx = d

	return nil
}

// FromProto converts a proto Transaction (assumed to be EIP-7702) into a TxEIP7702
func (tx *TxEIP7702) FromProto(pb *txProto.Transaction) error {
	if pb == nil {
		return ErrNilProtoTx
	}

	wrapper, ok := pb.Payload.(*txProto.Transaction_Eip7702)
	if !ok || wrapper.Eip7702 == nil {
		return ErrInvalidProtoEIP7702Tx
	}

	eip := wrapper.Eip7702

	// Make sure the recipient address is set (contract deployment is not allowed)
	if len(pb.GetTo()) != addressSize {
		return fmt.Errorf("%w: to: %d bytes, want %d", ErrInvalidProtoEIP7702Tx, len(pb.GetTo()), addressSize)
	}

	authorizations, err := authorizationListFromProto(eip.AuthorizationList)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProtoEIP7702Tx, err)
	}

	d := TxEIP7702{
		ChainID:              new(big.Int).SetBytes(eip.ChainId),
		MaxPriorityFeePerGas: new(big.Int).SetBytes(eip.MaxPriorityFeePerGas),
		MaxFeePerGas:         new(big.Int).SetBytes(eip.MaxFeePerGas),
		Value:                new(big.Int).SetBytes(pb.Value),
		YParity:              new(big.Int).SetBytes(pb.V), // the y parity is stored in the 'v' field
		R:                    new(big.Int).SetBytes(pb.R),
		S:                    new(big.Int).SetBytes(pb.S),
		Data:                 pb.Data,
		AuthorizationList:    authorizations,
		To:                   BytesToAddress(pb.GetTo()),
		Nonce:                pb.Nonce,
		Gas:                  pb.Gas,
	}

	d.AccessList.FromProto(eip.AccessList)

	*tx = d

	return nil
}

// ToProto converts the TxEIP7702 into its proto Transaction representation
func (tx *TxEIP7702) ToProto() *txProto.Transaction {
	return &txProto.Transaction{
		Nonce: tx.Nonce,
		To:    tx.To.ToBytes(),
		Gas:   tx.Gas,
		Value: bigToBytes(tx.Value),
		Data:  tx.Data,
		V:     bigToBytes(tx.YParity), // the y parity is stored in the 'v' field
		R:     bigToBytes(tx.R),
		S:     bigToBytes(tx.S),
		Payload: &txProto.Transaction_Eip7702{
			Eip7702: &txProto.EIP7702{
				MaxPriorityFeePerGas: bigToBytes(tx.MaxPriorityFeePerGas),
				MaxFeePerGas:         bigToBytes(tx.MaxFeePerGas),
				AccessList:           tx.AccessList.ToProto(),
				ChainId:              bigToBytes(tx.ChainID),
				AuthorizationList:    tx.AuthorizationList.toProto(),
			},
		},
	}
}
