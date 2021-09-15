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
