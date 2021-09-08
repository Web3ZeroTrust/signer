package did

import (
	"crypto/sha256"
	"fmt"

	"github.com/libs4go/crypto/hash160"
	"github.com/libs4go/encoding/base58"
)

func PubKey2ID(pubkey []byte, vendor string, version byte) string {
	pubBytes := pubkey

	var nonce []byte

	if len(pubBytes) < 32 {
		nonce = make([]byte, 32)
		copy(nonce[:], pubBytes)
	} else {
		nonce = pubBytes[:32]
	}

	hashed := hash160.Hash160(nonce)

	hasher := sha256.New()

	hasher.Write(hashed)

	sum := hasher.Sum(nil)

	hasher.Reset()

	hasher.Write(sum)

	sum = hasher.Sum(nil)

	sum = sum[:3]

	did := append(hashed, sum...)

	return fmt.Sprintf("did:%s:%s", vendor, base58.CheckEncode(did, version))
}
