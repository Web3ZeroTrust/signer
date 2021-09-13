package signer

import (
	"context"
	"crypto/elliptic"
	"math/big"
	"time"

	"github.com/libs4go/errors"
)

// ScopeOfAPIError .
const errVendor = "ethers-abi"

// errors
var (
	ErrNotFound = errors.New("Resource not found", errors.WithVendor(errVendor), errors.WithCode(-1))
)

// CryptoProvider crypto provider service
type CryptoProvider interface {
	// Export mnemonic
	Export(ctx context.Context, password string, tenancyID string) (mnemonic string, err error)
	// Import tenancy with mnemonic
	Import(ctx context.Context, password string, mnemonic string) (tenancyID string, err error)
	// Open and create new crypto provider and keystore
	Open(ctx context.Context, password string) (tenancyID string, err error)
	// Close close crypto provider and rm keystore
	Close(ctx context.Context, tenancyID string) error
	// OpenKey open new key
	OpenKey(ctx context.Context, password string, tenancyID string, bip44Path string) (keyID string, err error)
	// Sign call key sign
	Sign(ctx context.Context, password string, keyID string, curve elliptic.Curve, hashed []byte) (r *big.Int, s *big.Int, v *big.Int, err error)
	// CloseKey close key
	CloseKey(ctx context.Context, keyID string) error
	// Generate public keys
	PublicKeys(ctx context.Context, password string, keyID string, curves []elliptic.Curve) (pubkeys [][]byte, err error)
}

// StorageOps storage operator options
type StorageOps struct {
	Encrypt bool
}

// Storage op function
type StorageOp func(ops *StorageOps)

// KeyStore service
type KeyStore interface {
	Put(ctx context.Context, key []byte, value []byte, ops ...StorageOp) error
	Get(ctx context.Context, key []byte, ops ...StorageOp) (value []byte, err error)
	Delete(ctx context.Context, key []byte, ops ...StorageOp) (err error)
}

type Wallet struct {
	ID        string            `json:"id"`
	TenancyID string            `json:"tenancy" xorm:"unique 'tenancy_bip44_path'"`
	BIP44Path string            `json:"bip44path" xorm:"unique 'tenancy_bip44_path'"`
	Addresses map[string]string `json:"address"`
	Created   time.Time         `json:"created" xorm:"created"`
}

type Tenancy struct {
	ID      string    `json:"id"`
	Wallets uint      `json:"wallets"`
	Created time.Time `json:"created" xorm:"created"`
	Updated time.Time `json:"updated" xorm:"updated"`
}

type MultiTenancy interface {
	ExportTenancy(ctx context.Context, password string, tenancyID string) (data []byte, err error)
	ImportTenancy(ctx context.Context, password string, data []byte) (tenancyID string, err error)
	NewTenancy(ctx context.Context, password string) (tenancyID string, err error)
	TenancyCount(ctx context.Context) (count uint, err error)
	Tenancies(ctx context.Context, offset uint, count uint) (tenancies []*Tenancy, err error)
	WalletCount(ctx context.Context, tenancyID string) (count uint, err error)
	Wallets(ctx context.Context, tenancyID string, offset uint, count uint) (wallets []*Wallet, err error)
	OpenWallet(ctx context.Context, password string, tenancyID string, bip44Path string) (wallet *Wallet, err error)
	Sign(ctx context.Context, password string, walletID string, curve elliptic.Curve, hashed []byte) (r *big.Int, s *big.Int, v *big.Int, err error)
	CloseWallet(ctx context.Context, walletID string) error
}

type TenancyStorage interface {
	SaveTenancy(ctx context.Context, wallet *Wallet) error
	DeleteTenancy(ctx context.Context, walletID string) error
	TenancyCount(ctx context.Context) (count uint, err error)
	Tenancies(ctx context.Context, offset uint, count uint) (tenancies []*Tenancy, err error)
	SaveWallet(ctx context.Context, wallet *Wallet) error
	DeleteWallet(ctx context.Context, walletID string) error
	WalletCount(ctx context.Context, tenancyID string) (count uint, err error)
	Wallets(ctx context.Context, tenancyID string, offset uint, count uint) (wallets []*Wallet, err error)
}
