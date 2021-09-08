package signer

import (
	"context"
	"crypto/elliptic"
	"math/big"

	ethersigner "github.com/libs4go/ethers/signer"
)

// TrustClient trust client context
type TrustClient struct {
	ID    string // client id
	Token string // client session token
}

type EthersSigner interface {
	// Ether wallet receive address
	Addresss(ctx context.Context, client *TrustClient) string
	// SignTypedData implement eip712 sign ...
	SignTypedData(ctx context.Context, client *TrustClient, typedData *ethersigner.TypedData) ([]byte, error)
	// SignTransaction sign ether transaction
	SignTransaction(ctx context.Context, client *TrustClient, tx *ethersigner.Transaction) error
}

type CryptoProvider interface {
	// if return empty string "", call CreateHDWallet to initialize crypto provider
	ID(ctx context.Context) (string, error)
	// Create HDWallet and return wallet id
	CreateHDWallet(ctx context.Context, adminPassword string) (id string, err error)
	// Delete HDWallet by id
	DeleteHDWallet(ctx context.Context, adminPassword string) error

	// Create or return exists drived wallet publickey and save private key protected by password to keystore
	OpenSession(ctx context.Context, adminPassword string, sessionPassword string, bip44Path string) (string, error)
	// Sign data with bip44 drived wallet
	Sign(ctx context.Context, session string, password string, curve elliptic.Curve, hash []byte, compressed bool) (*big.Int, *big.Int, *big.Int, error)
	// Remove private key from keystore
	CloseSession(ctx context.Context, session string) error
}

type KeyStore interface {
	Put(ctx context.Context, key []byte, value []byte, force bool) (err error)
	Get(ctx context.Context, key []byte) ([]byte, error)
	Delete(ctx context.Context, key []byte) error
}
