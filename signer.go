package signer

import (
	"context"
	"crypto/elliptic"
	"math/big"

	"github.com/libs4go/errors"
)

// ScopeOfAPIError .
const errVendor = "ethers-abi"

// errors
var (
	ErrNotFound = errors.New("Resource not found", errors.WithVendor(errVendor), errors.WithCode(-1))
)

// // TrustClient trust client context
// type TrustClient struct {
// 	ID    string // client id
// 	Token string // client session token
// }

// type EthersSigner interface {
// 	// Ether wallet receive address
// 	Addresss(ctx context.Context, client *TrustClient) string
// 	// SignTypedData implement eip712 sign ...
// 	SignTypedData(ctx context.Context, client *TrustClient, typedData *ethersigner.TypedData) ([]byte, error)
// 	// SignTransaction sign ether transaction
// 	SignTransaction(ctx context.Context, client *TrustClient, tx *ethersigner.Transaction) error
// }

type CryptoProvider interface {
	// if return empty string "", call CreateHDWallet to initialize crypto provider
	ID(ctx context.Context) (string, error)
	// Create HDWallet and return wallet id
	CreateHDWallet(ctx context.Context, adminPassword string) (id string, err error)
	// Delete HDWallet by id
	DeleteHDWallet(ctx context.Context, adminPassword string) error

	// Create or return exists drived wallet publickey and save private key protected by password to keystore
	OpenKey(ctx context.Context, adminPassword string, sessionPassword string, bip44Path string, curves []elliptic.Curve) (string, [][]byte, error)
	// Sign data with bip44 drived wallet
	Sign(ctx context.Context, keyID string, password string, curve elliptic.Curve, hash []byte, compressed bool) (*big.Int, *big.Int, *big.Int, error)
	// Remove private key from keystore
	CloseKey(ctx context.Context, keyID string) error
	// Get Key public key
	KeyPublicKey(ctx context.Context, keyID string, password string, curves []elliptic.Curve) ([][]byte, error)
}

type KeyStoreOps struct {
	Force   bool
	Encrypt bool
}

type KeyStoreOp func(ops *KeyStoreOps)

func KeyStoreForce() KeyStoreOp {
	return func(ops *KeyStoreOps) {
		ops.Force = true
	}
}

func KeyStoreEncrypt() KeyStoreOp {
	return func(ops *KeyStoreOps) {
		ops.Encrypt = true
	}
}

type KeyStore interface {
	Put(ctx context.Context, key []byte, value []byte, ops ...KeyStoreOp) (err error)
	Get(ctx context.Context, key []byte, ops ...KeyStoreOp) ([]byte, error)
	Delete(ctx context.Context, key []byte, ops ...KeyStoreOp) error
}
