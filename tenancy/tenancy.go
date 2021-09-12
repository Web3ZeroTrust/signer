package tenancy

import (
	"context"

	"github.com/bwmarrin/snowflake"
	"github.com/libs4go/errors"
	"github.com/libs4go/scf4go"
	"github.com/web3zerotrust/signer"
)

type multiTenancyImpl struct {
	Storage        signer.MultiTenancyStorage `inject:"signer.MultiTenancyStorage"`
	CryptoProvider signer.CryptoProvider      `inject:"signer.CryptoProvider"`
	WalletProvider signer.WalletProvider      `inject:"signer.WalletProvider"`
	idSEQ          *snowflake.Node
}

func New(config scf4go.Config) (signer.MultiTenancyProvider, error) {

	idSEQ, err := snowflake.NewNode(int64(config.Get("cluster", "id").Int(1)))

	if err != nil {
		return nil, errors.Wrap(err, "create id seq error")
	}

	return &multiTenancyImpl{
		idSEQ: idSEQ,
	}, nil
}

func (impl *multiTenancyImpl) New(ctx context.Context, walletCold signer.WalletAddresses, adminPassword string) (userID string, err error) {
	userID := impl.idSEQ.Generate().String()
	// signer.Tenancy{}
	hostBIP44Path, err := impl.BIP44Provider.NewBIP44(ctx, userID, false)

	if err != nil {
		return "", err
	}

	backupBIP44Path, err := impl.BIP44Provider.NewBIP44(ctx, userID, true)

	if err != nil {
		return "", err
	}

	impl.CryptoProvider.OpenKey(ctx, adminPassword)

	return "", nil
}

func (impl *multiTenancyImpl) Delete(ctx context.Context, userID string) error {
	return nil
}

func (impl *multiTenancyImpl) User(ctx context.Context, userID string) (*signer.Tenancy, error) {
	return nil, nil
}

func (impl *multiTenancyImpl) RefreshWallet(ctx context.Context, userID string, password string) (*signer.Tenancy, error) {
	return nil, nil
}

func (impl *multiTenancyImpl) UpdateColdWallet(ctx context.Context, userID string, walletCold signer.WalletAddresses) error {
	return nil
}
