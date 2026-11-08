package ethtypes

import (
	"errors"

	"github.com/sig-0/ethrlp"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var ErrNilProtoWithdrawal = errors.New("proto withdrawal is nil")

// Withdrawal represents a validator withdrawal,
// introduced as part of EIP-4895 (Shanghai hardfork)
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4895.md
type Withdrawal struct {
	Address        Address // the recipient address
	Index          uint64  // the withdrawal index
	ValidatorIndex uint64  // the validator index
	Amount         uint64  // the withdrawn amount (in gwei)
}

// ToRLP encodes the withdrawal using RLP encoding.
//
// rlp([index, validatorIndex, address, amount])
func (w Withdrawal) ToRLP() []byte {
	return ethrlp.EncodeArray([][]byte{
		ethrlp.EncodeUint(w.Index),
		ethrlp.EncodeUint(w.ValidatorIndex),
		ethrlp.EncodeBytes(w.Address.ToBytes()),
		ethrlp.EncodeUint(w.Amount),
	})
}

// ToProto converts the withdrawal to its proto representation
func (w Withdrawal) ToProto() *ethProto.Withdrawal {
	return &ethProto.Withdrawal{
		Index:          w.Index,
		ValidatorIndex: w.ValidatorIndex,
		Recipient:      w.Address.ToBytes(),
		Amount:         w.Amount,
	}
}

// FromProto converts a proto Withdrawal to a withdrawal
func (w *Withdrawal) FromProto(pb *ethProto.Withdrawal) error {
	if pb == nil {
		return ErrNilProtoWithdrawal
	}

	*w = Withdrawal{
		Address:        BytesToAddress(pb.Recipient),
		Index:          pb.Index,
		ValidatorIndex: pb.ValidatorIndex,
		Amount:         pb.Amount,
	}

	return nil
}
