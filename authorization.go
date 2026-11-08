package ethtypes

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/sig-0/ethrlp"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

var ErrInvalidRLPAuthorizationAddress = errors.New("invalid authorization address RLP encoding")

// Authorization is a single signed code delegation,
// introduced as part of EIP-7702
type Authorization struct {
	ChainID       *big.Int // the ID of the chain (0 for any chain)
	YParity, R, S *big.Int // the signature fields (y parity is {0, 1})
	Address       Address  // the address of the delegated code
	Nonce         uint64   // the signer nonce
}

// AuthorizationList is a wrapper for authorization entries
type AuthorizationList []Authorization

// toRLP encodes the authorization list to RLP (RLP list)
func (l AuthorizationList) toRLP() []byte {
	items := make([][]byte, 0, len(l))

	for _, a := range l {
		items = append(items, ethrlp.EncodeArray([][]byte{
			ethrlp.EncodeBytes(bigToBytes(a.ChainID)),
			ethrlp.EncodeBytes(a.Address.ToBytes()),
			ethrlp.EncodeUint(a.Nonce),
			ethrlp.EncodeBytes(bigToBytes(a.YParity)),
			ethrlp.EncodeBytes(bigToBytes(a.R)),
			ethrlp.EncodeBytes(bigToBytes(a.S)),
		}))
	}

	return ethrlp.EncodeArray(items)
}

// toProto converts the authorization list to a proto representation
func (l AuthorizationList) toProto() []*txProto.Authorization {
	pbs := make([]*txProto.Authorization, 0, len(l))

	for _, a := range l {
		pbs = append(pbs, &txProto.Authorization{
			ChainId: bigToBytes(a.ChainID),
			Address: a.Address.ToBytes(),
			Nonce:   a.Nonce,
			YParity: bigToBytes(a.YParity),
			R:       bigToBytes(a.R),
			S:       bigToBytes(a.S),
		})
	}

	return pbs
}

// authorizationListFromProto parses the authorization list from the proto representation
func authorizationListFromProto(pbs []*txProto.Authorization) (AuthorizationList, error) {
	list := make(AuthorizationList, 0, len(pbs))

	for i, pb := range pbs {
		if pb == nil {
			return nil, fmt.Errorf("authorization %d is nil", i)
		}

		if len(pb.Address) != addressSize {
			return nil, fmt.Errorf("authorization %d: address: %d bytes, want %d", i, len(pb.Address), addressSize)
		}

		list = append(list, Authorization{
			ChainID: new(big.Int).SetBytes(pb.ChainId),
			YParity: new(big.Int).SetBytes(pb.YParity),
			R:       new(big.Int).SetBytes(pb.R),
			S:       new(big.Int).SetBytes(pb.S),
			Address: BytesToAddress(pb.Address),
			Nonce:   pb.Nonce,
		})
	}

	return list, nil
}

// fromRLPValues parses the raw RLP values of a single authorization.
// It expects the structure to be:
//
// [chainID, address, nonce, yParity, r, s] (6 elements)
func (a *Authorization) fromRLPValues(listValues []ethrlp.Value) error {
	if len(listValues) != 6 {
		return fmt.Errorf(
			"invalid authorization RLP encoding length: %d, expected %d",
			len(listValues),
			6,
		)
	}

	var d Authorization

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

	// Decode the address
	if listValues[1].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for address, %s",
			listValues[1].GetType(),
		)
	}

	addressRaw, ok := listValues[1].GetValue().([]byte)
	if !ok || len(addressRaw) != addressSize {
		return ErrInvalidRLPAuthorizationAddress
	}

	d.Address = BytesToAddress(addressRaw)

	// Decode the nonce
	if listValues[2].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for nonce, %s",
			listValues[2].GetType(),
		)
	}

	nonceRaw, ok := listValues[2].GetValue().([]byte)
	if !ok || len(nonceRaw) > 8 || (len(nonceRaw) > 0 && nonceRaw[0] == 0) {
		return ErrInvalidRLPNonce
	}

	d.Nonce = big.NewInt(0).SetBytes(nonceRaw).Uint64()

	// Decode the y parity
	if listValues[3].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for y parity, %s",
			listValues[3].GetType(),
		)
	}

	yParityRaw, ok := listValues[3].GetValue().([]byte)
	if !ok || len(yParityRaw) > 1 || (len(yParityRaw) > 0 && yParityRaw[0] == 0) {
		return ErrInvalidRLPYParity
	}

	d.YParity = big.NewInt(0).SetBytes(yParityRaw)

	// Decode the r sig param
	if listValues[4].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for r sig param, %s",
			listValues[4].GetType(),
		)
	}

	rRaw, ok := listValues[4].GetValue().([]byte)
	if !ok || len(rRaw) > 32 || (len(rRaw) > 0 && rRaw[0] == 0) {
		return ErrInvalidRLPRParam
	}

	d.R = big.NewInt(0).SetBytes(rRaw)

	// Decode the s sig param
	if listValues[5].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for s sig param, %s",
			listValues[5].GetType(),
		)
	}

	sRaw, ok := listValues[5].GetValue().([]byte)
	if !ok || len(sRaw) > 32 || (len(sRaw) > 0 && sRaw[0] == 0) {
		return ErrInvalidRLPSParam
	}

	d.S = big.NewInt(0).SetBytes(sRaw)

	*a = d

	return nil
}
