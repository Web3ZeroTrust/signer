package signer

import (
	"context"

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
	OpenSession(ctx context.Context) error
}
