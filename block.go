package ethtypes

import (
	"errors"
	"fmt"

	"github.com/sig-0/ethrlp"
	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var ErrNilProtoBlock = errors.New("proto block is nil")

// Block is a single Ethereum block, containing the
// header and transactions
type Block struct {
	Header       *Header        // the block header
	Transactions []*Transaction // the full transaction set
	Uncles       []*Header      // uncle headers (usually empty)
}

// ToRLP encodes the block using RLP encoding
func (b *Block) ToRLP() ([]byte, error) {
	// Encode the header
	headerRLP, err := b.Header.ToRLP()
	if err != nil {
		return nil, fmt.Errorf("unable to encode header: %w", err)
	}

	// Encode the transactions
	txsRLP := make([][]byte, 0, len(b.Transactions))

	for _, tx := range b.Transactions {
		txRLP, err := tx.ToRLP()
		if err != nil {
			return nil, fmt.Errorf("unable to encode tx: %w", err)
		}

		txsRLP = append(txsRLP, txRLP)
	}

	// Encode the uncles
	unclesRLP := make([][]byte, 0, len(b.Uncles))

	for _, uncle := range b.Uncles {
		uncleRLP, err := uncle.ToRLP()
		if err != nil {
			return nil, fmt.Errorf("unable to encode uncle header: %w", err)
		}

		unclesRLP = append(unclesRLP, uncleRLP)
	}

	rlpPayload := [][]byte{
		headerRLP,
		ethrlp.EncodeArray(txsRLP),
		ethrlp.EncodeArray(unclesRLP),
	}

	// Perform the RLP encoding of the payload
	rlpEncoding := ethrlp.EncodeArray(rlpPayload)

	return rlpEncoding, nil
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

	b.Header = header
	b.Transactions = txs

	return nil
}

// ToProto converts a block to its proto representation
func (b *Block) ToProto() (*ethProto.Block, error) {
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

	return &ethProto.Block{
		Header:       headerProto,
		Transactions: txsProto,
	}, nil
}
