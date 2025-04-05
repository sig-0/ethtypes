package ethtypes

import (
	"math/big"
	"testing"

	ethProto "github.com/sig-0/ethtypes/proto/eth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccount_EOA(t *testing.T) {
	t.Parallel()

	t.Run("EOA account", func(t *testing.T) {
		t.Parallel()

		a := &Account{
			StorageRoot: ZeroStorageHash,
			CodeHash:    ZeroCodeHash,
		}

		assert.True(t, a.IsEOA())
	})

	t.Run("non-EOA account", func(t *testing.T) {
		t.Parallel()

		a := &Account{
			StorageRoot: StringToHash("one"),
			CodeHash:    StringToHash("code"),
		}

		assert.False(t, a.IsEOA())
	})
}

func TestAccount_Proto(t *testing.T) {
	t.Parallel()

	t.Run("nil proto account", func(t *testing.T) {
		t.Parallel()

		acc := new(Account)

		assert.ErrorIs(t, acc.FromProto(nil), ErrNilProtoAcc)
	})

	t.Run("from proto", func(t *testing.T) {
		t.Parallel()

		var (
			balance     = big.NewInt(100)
			nonce       = uint64(10)
			storageRoot = StringToHash("storage")
			codeHash    = StringToHash("code")
		)

		pb := &ethProto.Account{
			Balance:     balance.Bytes(),
			Nonce:       nonce,
			StorageRoot: storageRoot.ToBytes(),
			CodeHash:    codeHash.ToBytes(),
		}

		acc := new(Account)
		require.NoError(t, acc.FromProto(pb))

		assert.Equal(t, acc.CodeHash, codeHash)
		assert.Equal(t, acc.StorageRoot, storageRoot)
		assert.Equal(t, acc.Nonce, nonce)
		assert.Equal(t, acc.Balance.String(), balance.String())
	})

	t.Run("to proto", func(t *testing.T) {
		t.Parallel()

		var (
			balance     = big.NewInt(100)
			nonce       = uint64(10)
			storageRoot = StringToHash("storage")
			codeHash    = StringToHash("code")
		)

		acc := &Account{
			Balance:     balance,
			Nonce:       nonce,
			StorageRoot: storageRoot,
			CodeHash:    codeHash,
		}

		pb := acc.ToProto()

		assert.Equal(t, pb.CodeHash, codeHash.ToBytes())
		assert.Equal(t, pb.StorageRoot, storageRoot.ToBytes())
		assert.Equal(t, pb.Nonce, nonce)
		assert.Equal(t, pb.Balance, balance.Bytes())
	})

	t.Run("e2e proto", func(t *testing.T) {
		t.Parallel()

		var (
			balance     = big.NewInt(100)
			nonce       = uint64(10)
			storageRoot = StringToHash("storage")
			codeHash    = StringToHash("code")
		)

		acc := &Account{
			Balance:     balance,
			Nonce:       nonce,
			StorageRoot: storageRoot,
			CodeHash:    codeHash,
		}

		// Convert to proto
		pb := acc.ToProto()

		// Convert it back
		accFromProto := new(Account)
		require.NoError(t, accFromProto.FromProto(pb))

		// Make sure the accounts are the same
		assert.Equal(t, acc, accFromProto)
	})
}
