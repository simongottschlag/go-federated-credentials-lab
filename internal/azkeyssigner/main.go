package azkeyssigner

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type Signer struct {
	ctx        context.Context
	client     *azkeys.Client
	keyName    string
	keyVersion string
}

var _ crypto.Signer = (*Signer)(nil)

func New(ctx context.Context, client *azkeys.Client, keyName string, keyVersion string) *Signer {
	return &Signer{
		ctx:        ctx,
		client:     client,
		keyName:    keyName,
		keyVersion: keyVersion,
	}
}

func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signatureAlgorithm, err := s.getSignatureAlgorithm(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	signResponse, err := s.client.Sign(
		s.ctx,
		s.keyName,
		s.keyVersion,
		azkeys.SignParameters{
			Algorithm: signatureAlgorithm,
			Value:     digest,
		},
		&azkeys.SignOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to sign the hashed digest: %w", err)
	}

	if signResponse.KID == nil {
		return nil, fmt.Errorf("signed response missing KID")
	}

	if signResponse.KID.Version() != s.keyVersion {
		return nil, fmt.Errorf("unexpected key version in the response %s (expected: %s)", signResponse.KID.Version(), s.keyVersion)
	}

	if signResponse.Result == nil {
		return nil, fmt.Errorf("missing signature result")
	}

	return signResponse.Result, nil
}

func (s *Signer) Public() crypto.PublicKey {
	keyResponse, err := s.client.GetKey(s.ctx, s.keyName, s.keyVersion, &azkeys.GetKeyOptions{})
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	jwk, err := getJWKfromKeyResponse(keyResponse)
	if err != nil {
		return fmt.Errorf("failed to get JWK from key response: %w", err)
	}

	rsaPublicKey, err := getRSAPublicKeyfromJWK(jwk)
	if err != nil {
		return fmt.Errorf("failed to get RSA public key from JWK: %w", err)
	}

	return rsaPublicKey
}

func (s *Signer) getSignatureAlgorithm(opts crypto.SignerOpts) (*azkeys.SignatureAlgorithm, error) {
	switch opts {
	case crypto.SHA256:
		return to.Ptr(azkeys.SignatureAlgorithmRS256), nil
	}
	return nil, fmt.Errorf("unsupported signature algorithm: %s", opts)
}

func getJWKfromKeyResponse(keyResponse azkeys.GetKeyResponse) (jwk.Key, error) {
	jsonKeyBytes, err := keyResponse.Key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	parsedJwk, err := jwk.ParseKey(jsonKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	return parsedJwk, nil
}

func getRSAPublicKeyfromJWK(key jwk.Key) (*rsa.PublicKey, error) {
	publicRSAKey := &rsa.PublicKey{}
	err := jwk.Export(key, publicRSAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to export jwk to public rsa key: %w", err)
	}

	return publicRSAKey, nil
}

// func getPublicKeyPEMfromRSAPublicKey(rsaKey *rsa.PublicKey) ([]byte, error) {
// 	publicKeyPEM := &pem.Block{
// 		Type:  "RSA PUBLIC KEY",
// 		Bytes: x509.MarshalPKCS1PublicKey(rsaKey),
// 	}

// 	encodedPublicKeyPEM := pem.EncodeToMemory(publicKeyPEM)
// 	if encodedPublicKeyPEM == nil {
// 		return nil, fmt.Errorf("failed to encode public key to PEM")
// 	}

// 	return encodedPublicKeyPEM, nil
// }
