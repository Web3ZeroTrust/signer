package crypto

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"math/big"

	"github.com/libs4go/crypto/bip32"
	"github.com/libs4go/crypto/bip39"
	ecdsax "github.com/libs4go/crypto/ecdsa"
	ellipticx "github.com/libs4go/crypto/elliptic"
	"github.com/libs4go/encoding/web3"
	"github.com/libs4go/errors"
	"github.com/libs4go/scf4go"
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

var keyVendor = "trust-signer-key"
var keyVersion = byte(20)

var idKey = "__crypto_provider_id"

var mnemonicKey = "__crypto_provider_mnemonic"

type providerImpl struct {
	KeyStore signer.KeyStore `inject:"signer.KeyStore"`
}

// New create new signer crypto provider
func New(config scf4go.Config) (signer.CryptoProvider, error) {
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
	entropy, err := bip39.NewEntropy(24 * 8)

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

	err = impl.KeyStore.Put(ctx, []byte(mnemonicKey), buff.Bytes(), signer.KeyStoreForce())

	if err != nil {
		return "", err
	}

	err = impl.KeyStore.Put(ctx, []byte(idKey), []byte(id), signer.KeyStoreForce())

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

	err = impl.KeyStore.Put(ctx, key, buff.Bytes(), signer.KeyStoreForce())

	if err != nil {
		return err
	}

	return nil
}

func (impl *providerImpl) getWithPassword(ctx context.Context, key []byte, password string) ([]byte, error) {
	data, err := impl.KeyStore.Get(ctx, key)

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

func (impl *providerImpl) OpenKey(ctx context.Context, adminPassword string, sessionPassword string, bip44Path string, curves []elliptic.Curve) (string, [][]byte, error) {
	drivedKey, err := impl.drivedKey(ctx, adminPassword, bip44Path)

	if err != nil {
		return "", nil, err
	}

	keyID := did.PubKey2ID(drivedKey.PublicKey, keyVendor, keyVersion)

	err = impl.saveWithPassword(ctx, []byte(keyID), drivedKey.PrivateKey, sessionPassword)

	if err != nil {
		return "", nil, err
	}

	var pubKeys [][]byte

	for _, curve := range curves {
		privateKey := ecdsax.BytesToPrivateKey(drivedKey.PrivateKey, curve)
		pubKeys = append(pubKeys, ecdsax.PublicKeyBytes(&privateKey.PublicKey))
	}

	return keyID, pubKeys, nil
}

func (impl *providerImpl) Sign(ctx context.Context, keyID string, password string, curve elliptic.Curve, hash []byte, compressed bool) (*big.Int, *big.Int, *big.Int, error) {

	buff, err := impl.getWithPassword(ctx, []byte(keyID), password)

	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "key(%s) not found", keyID)
	}

	privateKey := ecdsax.BytesToPrivateKey(buff, curve)

	return ecdsax.RecoverSign(privateKey, hash, compressed)
}

func (impl *providerImpl) CloseKey(ctx context.Context, keyID string) error {
	return impl.KeyStore.Delete(ctx, []byte(keyID))
}

func (impl *providerImpl) KeyPublicKey(ctx context.Context, keyID string, password string, curves []elliptic.Curve) ([][]byte, error) {
	buff, err := impl.getWithPassword(ctx, []byte(keyID), password)

	if err != nil {
		return nil, errors.Wrap(err, "key(%s) not found", keyID)
	}

	var pubKeys [][]byte

	for _, curve := range curves {
		privateKey := ecdsax.BytesToPrivateKey(buff, curve)
		pubKeys = append(pubKeys, ecdsax.PublicKeyBytes(&privateKey.PublicKey))
	}

	return pubKeys, nil

}
