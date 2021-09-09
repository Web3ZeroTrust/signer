package keystore

import (
	"context"
	"encoding/hex"

	"github.com/libs4go/errors"
	"github.com/web3zerotrust/signer"
)

type memoryKeyStore struct {
	kvs map[string][]byte
}

func NewMemory() signer.KeyStore {
	return &memoryKeyStore{
		kvs: make(map[string][]byte),
	}
}

func (memory *memoryKeyStore) Put(ctx context.Context, key []byte, value []byte, ops ...signer.KeyStoreOp) (err error) {
	buff := make([]byte, len(value))
	copy(buff, value)
	memory.kvs[hex.EncodeToString(key)] = buff
	return nil
}

func (memory *memoryKeyStore) Get(ctx context.Context, key []byte, ops ...signer.KeyStoreOp) ([]byte, error) {
	value, ok := memory.kvs[hex.EncodeToString(key)]

	if !ok {
		return nil, errors.Wrap(signer.ErrNotFound, "key value(%s) not found", hex.EncodeToString(key))
	}

	buff := make([]byte, len(value))
	copy(buff, value)

	return buff, nil
}

func (memory *memoryKeyStore) Delete(ctx context.Context, key []byte, ops ...signer.KeyStoreOp) error {
	delete(memory.kvs, hex.EncodeToString(key))
	return nil
}
