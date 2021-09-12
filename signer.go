package signer

import (
	"context"
	"crypto/elliptic"
	"math/big"
	"time"

	"github.com/libs4go/errors"
	"github.com/libs4go/ethers/signer"
)

// ScopeOfAPIError .
const errVendor = "ethers-abi"

// errors
var (
	ErrNotFound = errors.New("Resource not found", errors.WithVendor(errVendor), errors.WithCode(-1))
)

type EthersSigner interface {
	// Ether wallet receive address
	Addresss(ctx context.Context, userID string) string
	// SignTypedData implement eip712 sign ...
	SignTypedData(ctx context.Context, userID string, typedData *signer.TypedData) ([]byte, error)
	// SignTransaction sign ether transaction
	SignTransaction(ctx context.Context, userID string, tx *signer.Transaction) error
}

// TenancyWallet hold signer generate wallet inforamtion
type TenancyWallet struct {
	KeyID     string            // wallet binding crypto provider key
	BIP44Path string            // wallet bip44 path
	Addresses map[string]string // wallet addresses
}

type Tenancy struct {
	ID           string          // user id
	WalletHot    *TenancyWallet  // hot user wallets
	WalletBackup *TenancyWallet  // backup wallet
	WalletCold   WalletAddresses //  cold wallet addresses
	CreatedTime  time.Time       // tenancy created time
	UpdatedTime  time.Time       // tenancy last update time
}

type WalletAddresses map[string]string

type MultiTenancyProvider interface {
	// create new user, and Generate wallets
	New(ctx context.Context, walletCold WalletAddresses, adminPassword string) (userID string, err error)
	// remove user
	Delete(ctx context.Context, userID string) error
	// Get wallet data
	User(ctx context.Context, userID string) (*Tenancy, error)
	// Regenerate signer manager wallet keys
	RefreshWallet(ctx context.Context, userID string, adminPassword string) (*Tenancy, error)
	// Update cold wallet
	UpdateColdWallet(ctx context.Context, userID string, walletCold WalletAddresses) error
}

type MultiTenancyStorage interface {
	New(ctx context.Context, tenancy *Tenancy) error
	Delete(ctx context.Context, id string) error
	Get(ctx context.Context, id string) (*Tenancy, error)
	Update(ctx context.Context, id string, txF func(ctx context.Context, tenancy *Tenancy, updateF func(tenancy *Tenancy) error) error) error
}

type WalletProvider interface {
	NewBIP44Wallet(ctx context.Context, id string, internal bool, adminPassword string) (path string, password string, err error)
	Password(ctx context.Context, id string, bip44path string)
}

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

// KeyStore ....

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
