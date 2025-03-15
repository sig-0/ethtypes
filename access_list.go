package ethtypes

import (
	"errors"
	"fmt"

	"github.com/sig-0/ethrlp"
	txProto "github.com/sig-0/ethtypes/proto/eth/v1"
)

// AccessList is a wrapper for access list entries
type AccessList []AccessListEntry

// AccessListEntry is a single access list entry,
// denoting the accessed storage keys (hashes) and address
type AccessListEntry struct {
	StorageKeys []Hash  `json:"storageKeys"`
	Address     Address `json:"address"`
}

// FromRLP parses the RLP encoding of an access list
func (l *AccessList) FromRLP(data []byte) error {
	// Decode the RLP data
	list, err := ethrlp.DecodeBytes(data)
	if err != nil {
		return fmt.Errorf("failed to decode access list RLP data: %w", err)
	}

	if list.GetType() != ethrlp.List {
		return fmt.Errorf("invalid access list RLP encoding type: %s", list.GetType())
	}

	listValues, ok := list.GetValue().([]ethrlp.Value)
	if !ok {
		return fmt.Errorf("invalid access list RLP encoding type: %s", list.GetValue())
	}

	return l.FromRLPValues(listValues)
}

// FromRLPValues parses the raw RLP values of an access list
func (l *AccessList) FromRLPValues(listValues []ethrlp.Value) error {
	for _, entryRaw := range listValues {
		if entryRaw.GetType() != ethrlp.Bytes {
			return errors.New("invalid access list entry RLP encoding")
		}

		entry, ok := entryRaw.GetValue().([]byte)
		if !ok || entry == nil {
			return errors.New("invalid access list entry RLP encoding")
		}

		var acEntry AccessListEntry

		if err := acEntry.FromRLP(entry); err != nil {
			return fmt.Errorf("invalid access list entry RLP encoding: %w", err)
		}

		*l = append(*l, acEntry)
	}

	return nil
}

// ToRLP encodes the access list to RLP (RLP list)
func (l AccessList) ToRLP() []byte {
	encodedEntries := make([][]byte, 0, len(l))

	for _, entry := range l {
		encodedEntries = append(
			encodedEntries,
			entry.ToRLP(),
		)
	}

	rlpEncoding := ethrlp.EncodeArray(encodedEntries)

	return rlpEncoding
}

// ToProto converts the access list to a proto representation
func (l AccessList) ToProto() []*txProto.AccessListEntry {
	entries := make([]*txProto.AccessListEntry, len(l))

	for i, entry := range l {
		entries[i] = entry.ToProto()
	}

	return entries
}

// FromProto parses the access list from the proto representation
func (l *AccessList) FromProto(protoList []*txProto.AccessListEntry) {
	if protoList == nil {
		*l = nil

		return
	}

	entries := make([]AccessListEntry, len(protoList))
	for i, entry := range protoList {
		entries[i].FromProto(entry)
	}

	*l = entries
}

// FromRLP parses the RLP encoding of a single access list entry
func (e *AccessListEntry) FromRLP(data []byte) error {
	// Decode the RLP data
	list, err := ethrlp.DecodeBytes(data)
	if err != nil {
		return fmt.Errorf("failed to decode access list RLP data: %w", err)
	}

	if list.GetType() != ethrlp.List {
		return fmt.Errorf("invalid access list RLP encoding type: %s", list.GetType())
	}

	listValues, _ := list.GetValue().([]ethrlp.Value)
	if len(listValues) != 2 {
		return fmt.Errorf(
			"invalid access list entry RLP encoding length: %d, expected %d",
			len(listValues),
			2,
		)
	}

	// Decode the address
	if listValues[0].GetType() != ethrlp.Bytes {
		return fmt.Errorf(
			"invalid RLP encoding type for address param, %s",
			listValues[0].GetType(),
		)
	}

	addressRaw, ok := listValues[0].GetValue().([]byte)
	if !ok || addressRaw == nil {
		return errors.New("invalid address param RLP encoding")
	}

	e.Address = BytesToAddress(addressRaw)

	// Decode the storage keys
	if listValues[1].GetType() != ethrlp.List {
		return fmt.Errorf(
			"invalid RLP encoding type for storage keys param, %s",
			listValues[1].GetType(),
		)
	}

	var (
		storageKeysList, _ = listValues[1].GetValue().([]ethrlp.Value)
		storageKeys        = make([]Hash, 0, len(storageKeysList))
	)

	for _, storageKey := range storageKeysList {
		storageKeyRaw, ok := storageKey.GetValue().([]byte)
		if !ok || storageKeyRaw == nil {
			return errors.New("invalid storage key param RLP encoding")
		}

		storageKeys = append(storageKeys, BytesToHash(storageKeyRaw))
	}

	e.StorageKeys = storageKeys

	return nil
}

// ToRLP encodes the single access list entry to RLP (RLP Bytes)
func (e AccessListEntry) ToRLP() []byte {
	encodedStorageKeys := make([][]byte, 0, len(e.StorageKeys))

	for _, storageKey := range e.StorageKeys {
		encodedStorageKeys = append(
			encodedStorageKeys,
			ethrlp.EncodeBytes(storageKey.ToBytes()),
		)
	}

	rlpEncoding := ethrlp.EncodeArray([][]byte{
		ethrlp.EncodeBytes(e.Address.ToBytes()),
		ethrlp.EncodeArray(encodedStorageKeys),
	})

	return rlpEncoding
}

// ToProto converts the single access list entry to a proto representation
func (e AccessListEntry) ToProto() *txProto.AccessListEntry {
	storageKeys := make([][]byte, 0, len(e.StorageKeys))

	for _, storageKey := range e.StorageKeys {
		storageKeys = append(storageKeys, storageKey.ToBytes())
	}

	return &txProto.AccessListEntry{
		Address:     e.Address.ToBytes(),
		StorageKeys: storageKeys,
	}
}

// FromProto parses the proto representation of an access list entry
func (e *AccessListEntry) FromProto(protoEntry *txProto.AccessListEntry) {
	e.Address = BytesToAddress(protoEntry.GetAddress())
	e.StorageKeys = make([]Hash, 0, len(protoEntry.GetStorageKeys()))

	for _, storageKey := range protoEntry.StorageKeys {
		e.StorageKeys = append(e.StorageKeys, BytesToHash(storageKey))
	}
}
