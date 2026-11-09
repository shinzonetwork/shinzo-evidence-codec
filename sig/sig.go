// Package sig verifies a generator's signature over a statement.
package sig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// TypeES256K is the type of a signature made with a secp256k1 key.
const TypeES256K = "ES256K"

// Errors returned by VerifyStatement.
var (
	ErrUnsupportedType = errors.New("unsupported signature type")
	ErrSigner          = errors.New("signer is not a compressed secp256k1 public key")
	ErrInvalid         = errors.New("signature does not verify")
)

// VerifyStatement returns nil when signature is signer's signature over statement. signer is a compressed public
// key in hex, and signature is the hex DER encoding of an ECDSA signature over the SHA-256 of statement.
func VerifyStatement(statement []byte, signer, typ, signature string) error {
	if typ != TypeES256K {
		return fmt.Errorf("%w: %q", ErrUnsupportedType, typ)
	}
	raw, err := hex.DecodeString(signer)
	if err != nil || len(raw) != secp256k1.PubKeyBytesLenCompressed {
		return fmt.Errorf("%w: %q", ErrSigner, signer)
	}
	key, err := secp256k1.ParsePubKey(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSigner, err)
	}
	der, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	parsed, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	hash := sha256.Sum256(statement)
	if !parsed.Verify(hash[:], key) {
		return ErrInvalid
	}
	return nil
}
