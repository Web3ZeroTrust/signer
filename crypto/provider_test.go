package crypto

import (
	"context"
	"crypto/elliptic"

	"testing"

	ecdsax "github.com/libs4go/crypto/ecdsa"
	"github.com/libs4go/crypto/hash160"
	"github.com/libs4go/errors"
	"github.com/libs4go/scf4go"
	_ "github.com/libs4go/scf4go/codec/json"
	"github.com/stretchr/testify/require"
	"github.com/web3zerotrust/signer"
	"github.com/web3zerotrust/signer/keystore"
)

func createCrypto() (signer.CryptoProvider, error) {
	config := scf4go.New()
	provider, err := New(config)

	if err != nil {
		return nil, err
	}

	impl := provider.(*providerImpl)

	impl.KeyStore = keystore.NewMemory()

	return provider, nil
}

func TestCreateHDWallet(t *testing.T) {

	provider, err := createCrypto()

	require.NoError(t, err)

	id, err := provider.ID(context.Background())

	require.True(t, errors.Is(err, signer.ErrNotFound))

	require.Equal(t, id, "")

	newID, err := provider.CreateHDWallet(context.Background(), "test")

	require.NoError(t, err)

	id, err = provider.ID(context.Background())

	require.NoError(t, err)

	require.NotEqual(t, id, "")

	require.Equal(t, newID, id)

	keID, pubKeys, err := provider.OpenKey(context.Background(), "test", "test1", "m/44'/60'/0'/0/0", []elliptic.Curve{elliptic.P224()})

	require.NoError(t, err)

	require.NotEqual(t, keID, "")

	require.Equal(t, len(pubKeys), 1)

	hash := hash160.Hash160([]byte("Hello"))

	r, s, v, err := provider.Sign(context.Background(), keID, "test1", elliptic.P224(), hash, true)

	require.NoError(t, err)

	pubKey2, compressed, err := ecdsax.Recover(elliptic.P224(), r, s, v, hash)

	require.NoError(t, err)

	require.Equal(t, ecdsax.PublicKeyBytes(pubKey2), pubKeys[0])

	require.Equal(t, compressed, true)

	err = provider.CloseKey(context.TODO(), keID)

	require.NoError(t, err)

	_, _, _, err = provider.Sign(context.Background(), keID, "test1", elliptic.P521(), hash, true)

	require.True(t, errors.Is(err, signer.ErrNotFound))
}
