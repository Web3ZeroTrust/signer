package crypto

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"

	"github.com/libs4go/crypto/bip32"
	"github.com/libs4go/crypto/bip39"
	ecdsax "github.com/libs4go/crypto/ecdsa"
	ellipticx "github.com/libs4go/crypto/elliptic"
	"github.com/libs4go/encoding/web3"
	"github.com/libs4go/errors"
	"github.com/libs4go/scf4go"
	"github.com/libs4go/smf4go"
	"github.com/web3zerotrust/signer"
	"github.com/web3zerotrust/signer/did"
)

type keyParam struct {
}

func (*keyParam) Curve() elliptic.Curve {
	return ellipticx.SECP256K1()
}

var kp = &keyParam{}

var didKeyPath = "m/44'/608581'/0'/0/0"
var didVendor = "trust-signer"
var didVersion = byte(20)

var sessionVendor = "trust-signer-session"
var sessionVersion = byte(20)

var idKey = "__crypto_provider_id"

var mnemonicKey = "__crypto_provider_mnemonic"

type providerImpl struct {
	KeyStore signer.KeyStore `inject:"signer.KeyStore"`
}

// New create new signer crypto provider
func New(config scf4go.Config) (smf4go.Service, error) {
	return &providerImpl{}, nil
}

func (impl *providerImpl) getMnemonic(ctx context.Context, password string) (string, error) {
	data, err := impl.KeyStore.Get(ctx, []byte(mnemonicKey))

	if err != nil {
		return "", err
	}

	mnemonic, err := web3.Standard().Decode(web3.Property{"password": password}, bytes.NewBuffer(data))

	if err != nil {
		return "", err
	}

	return string(mnemonic), nil
}

func (impl *providerImpl) drivedKey(ctx context.Context, password string, bip44Path string) (*bip32.DrivedKey, error) {
	mnemonic, err := impl.getMnemonic(ctx, password)

	if err != nil {
		return nil, err
	}

	rootKey, err := bip32.FromMnemonic(kp, mnemonic, "")

	if err != nil {
		return nil, err
	}

	return bip32.DriveFrom(rootKey, didKeyPath)
}

func (impl *providerImpl) ID(ctx context.Context) (string, error) {
	data, err := impl.KeyStore.Get(ctx, []byte(idKey))

	if err != nil {
		return "", err
	}

	if len(data) == 0 {
		return "", nil
	}

	return string(data), nil
}

func (impl *providerImpl) CreateHDWallet(ctx context.Context, adminPassword string) (string, error) {
	entropy, err := bip39.NewEntropy(21 * 8)

	if err != nil {
		return "", errors.Wrap(err, "Create Entropy(%d) error", 21)
	}

	mnemonic, err := bip39.NewMnemonic(entropy, bip39.ENUS())

	if err != nil {
		return "", err
	}

	rootKey, err := bip32.FromMnemonic(kp, mnemonic, "")

	if err != nil {
		return "", err
	}

	drivedKey, err := bip32.DriveFrom(rootKey, didKeyPath)

	if err != nil {
		return "", err
	}

	id := did.PubKey2ID(drivedKey.PublicKey, didVendor, didVersion)

	var buff bytes.Buffer

	err = web3.Standard().Encode([]byte(mnemonic), web3.Property{
		"address":  id,
		"password": adminPassword,
	}, &buff)

	if err != nil {
		return "", err
	}

	err = impl.KeyStore.Put(ctx, []byte(mnemonicKey), buff.Bytes(), true)

	if err != nil {
		return "", err
	}

	err = impl.KeyStore.Put(ctx, []byte(idKey), []byte(id), true)

	if err != nil {
		impl.forceDeleteHDWallet(ctx)
		return "", err
	}

	return id, err
}

func (impl *providerImpl) saveWithPassword(ctx context.Context, key []byte, data []byte, password string) error {

	var buff bytes.Buffer

	err := web3.Standard().Encode(data, web3.Property{
		"password": password,
	}, &buff)

	if err != nil {
		return err
	}

	err = impl.KeyStore.Put(ctx, []byte(mnemonicKey), buff.Bytes(), true)

	if err != nil {
		return err
	}

	return nil
}

func (impl *providerImpl) getWithPassword(ctx context.Context, key []byte, password string) ([]byte, error) {
	data, err := impl.KeyStore.Get(ctx, []byte(mnemonicKey))

	if err != nil {
		return nil, err
	}

	buff, err := web3.Standard().Decode(web3.Property{"password": password}, bytes.NewBuffer(data))

	if err != nil {
		return nil, err
	}

	return buff, nil
}

func (impl *providerImpl) forceDeleteHDWallet(ctx context.Context) error {
	impl.KeyStore.Delete(ctx, []byte(mnemonicKey))
	impl.KeyStore.Delete(ctx, []byte(idKey))

	return nil
}

func (impl *providerImpl) DeleteHDWallet(ctx context.Context, adminPassword string) error {
	_, err := impl.getMnemonic(ctx, adminPassword)

	if err != nil {
		return err
	}

	return impl.forceDeleteHDWallet(ctx)
}

func (impl *providerImpl) OpenSession(ctx context.Context, adminPassword string, sessionPassword string, bip44Path string) (string, error) {
	drivedKey, err := impl.drivedKey(ctx, adminPassword, bip44Path)

	if err != nil {
		return "", err
	}

	id := did.PubKey2ID(drivedKey.PublicKey, sessionVendor, sessionVersion)

	err = impl.saveWithPassword(ctx, []byte(id), drivedKey.PrivateKey, sessionPassword)

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(drivedKey.PublicKey), nil
}

func (impl *providerImpl) Sign(ctx context.Context, session string, password string, curve elliptic.Curve, hash []byte, compressed bool) (*big.Int, *big.Int, *big.Int, error) {

	buff, err := impl.getWithPassword(ctx, []byte(session), password)

	if err != nil {
		return nil, nil, nil, err
	}

	privateKey := ecdsax.BytesToPrivateKey(buff, curve)

	return ecdsax.RecoverSign(privateKey, hash, compressed)
}

func (impl *providerImpl) CloseSession(ctx context.Context, session string) error {
	return impl.KeyStore.Delete(ctx, []byte(session))
}
