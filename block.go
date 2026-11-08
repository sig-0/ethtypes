package ethtypes

import (
	"errors"
	"fmt"

	"github.com/sig-0/ethrlp"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var (
	ErrNilProtoBlock         = errors.New("proto block is nil")
	ErrNilBlockHeader        = errors.New("block header is nil")
	ErrUnexpectedWithdrawals = errors.New("withdrawals on a pre-Shanghai block")
)

// Block is a single Ethereum block, containing the
// header, transactions, uncles and withdrawals
type Block struct {
	Header       *Header        // Associated block header
	Transactions []*Transaction // List of transactions included in the block
	Uncles       []*Header      // List of uncle headers included in the block
	Withdrawals  []Withdrawal   // List of validator withdrawals included in the block
}

// ToRLP encodes the block using RLP encoding.
//
// - Pre-Shanghai RLP: [header, transactions, uncles] (3 elements)
//
// - Shanghai RLP: [header, transactions, uncles, withdrawals] (4 elements)
//
// Transactions are encoded in their signed form
func (b *Block) ToRLP() ([]byte, error) {
	if b.Header == nil {
		return nil, ErrNilBlockHeader
	}

	headerRLP, err := b.Header.ToRLP()
	if err != nil {
		return nil, fmt.Errorf("unable to encode header: %w", err)
	}

	txsRLP := make([][]byte, 0, len(b.Transactions))

	for _, tx := range b.Transactions {
		signed, err := tx.ToSignedRLP()
		if err != nil {
			return nil, fmt.Errorf("unable to encode transaction: %w", err)
		}

		if tx.Type() != TransactionLegacy {
			signed = ethrlp.EncodeBytes(signed)
		}

		txsRLP = append(txsRLP, signed)
	}

	unclesRLP := make([][]byte, 0, len(b.Uncles))

	for _, uncle := range b.Uncles {
		uncleRLP, err := uncle.ToRLP()
		if err != nil {
			return nil, fmt.Errorf("unable to encode uncle header: %w", err)
		}

		unclesRLP = append(unclesRLP, uncleRLP)
	}

	payload := [][]byte{headerRLP, ethrlp.EncodeArray(txsRLP), ethrlp.EncodeArray(unclesRLP)}

	// Encode the withdrawals (EIP-4895 headers and later)
	switch {
	case b.Header.inner.getType() >= headerEIP4895:
		withdrawalsRLP := make([][]byte, 0, len(b.Withdrawals))
		for _, w := range b.Withdrawals {
			withdrawalsRLP = append(withdrawalsRLP, w.ToRLP())
		}

		payload = append(payload, ethrlp.EncodeArray(withdrawalsRLP))
	case len(b.Withdrawals) > 0:
		return nil, ErrUnexpectedWithdrawals
	}

	return ethrlp.EncodeArray(payload), nil
}

// FromProto converts a proto Block to a block representation
func (b *Block) FromProto(pb *ethProto.Block) error {
	if pb == nil {
		return ErrNilProtoBlock
	}

	// Parse the header
	header := new(Header)
	if err := header.FromProto(pb.Header); err != nil {
		return fmt.Errorf("unable to parse header proto: %w", err)
	}

	// Parse the transactions
	txs := make([]*Transaction, 0, len(pb.Transactions))

	for _, protoTx := range pb.Transactions {
		tx := new(Transaction)

		if err := tx.FromProto(protoTx); err != nil {
			return fmt.Errorf("unable to parse tx proto: %w", err)
		}

		txs = append(txs, tx)
	}

	uncles := make([]*Header, 0, len(pb.Uncles))

	for _, protoUncle := range pb.Uncles {
		uncle := new(Header)

		if err := uncle.FromProto(protoUncle); err != nil {
			return fmt.Errorf("unable to parse uncle proto: %w", err)
		}

		uncles = append(uncles, uncle)
	}

	withdrawals := make([]Withdrawal, len(pb.Withdrawals))

	for i, protoWithdrawal := range pb.Withdrawals {
		if err := withdrawals[i].FromProto(protoWithdrawal); err != nil {
			return fmt.Errorf("unable to parse withdrawal proto: %w", err)
		}
	}

	*b = Block{
		Header:       header,
		Transactions: txs,
		Uncles:       uncles,
		Withdrawals:  withdrawals,
	}

	return nil
}

// ToProto converts a block to its proto representation
func (b *Block) ToProto() (*ethProto.Block, error) {
	if b.Header == nil {
		return nil, ErrNilBlockHeader
	}

	// Prepare the header
	headerProto, err := b.Header.ToProto()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal header: %w", err)
	}

	// Prepare the transactions
	txsProto := make([]*ethProto.Transaction, 0, len(b.Transactions))

	for _, tx := range b.Transactions {
		protoTx, err := tx.ToProto()
		if err != nil {
			return nil, fmt.Errorf("unable to marshal tx: %w", err)
		}

		txsProto = append(txsProto, protoTx)
	}

	unclesProto := make([]*ethProto.Header, 0, len(b.Uncles))

	for _, uncle := range b.Uncles {
		protoUncle, err := uncle.ToProto()
		if err != nil {
			return nil, fmt.Errorf("unable to marshal uncle: %w", err)
		}

		unclesProto = append(unclesProto, protoUncle)
	}

	withdrawalsProto := make([]*ethProto.Withdrawal, 0, len(b.Withdrawals))
	for _, w := range b.Withdrawals {
		withdrawalsProto = append(withdrawalsProto, w.ToProto())
	}

	return &ethProto.Block{
		Header:       headerProto,
		Transactions: txsProto,
		Withdrawals:  withdrawalsProto,
		Uncles:       unclesProto,
	}, nil
}
