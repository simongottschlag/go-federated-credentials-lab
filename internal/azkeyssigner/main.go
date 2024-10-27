package azkeyssigner

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type Signer struct {
	ctx     context.Context
	client  *azkeys.Client
	keyName string
}

var _ crypto.Signer = (*Signer)(nil)

const useLatestKeyVersion = ""

func New(ctx context.Context, client *azkeys.Client, keyName string) *Signer {
	return &Signer{
		ctx:     ctx,
		client:  client,
		keyName: keyName,
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
		useLatestKeyVersion,
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

	if signResponse.Result == nil {
		return nil, fmt.Errorf("missing signature result")
	}

	return signResponse.Result, nil
}

func (s *Signer) Public() crypto.PublicKey {
	keyResponse, err := s.client.GetKey(s.ctx, s.keyName, useLatestKeyVersion, &azkeys.GetKeyOptions{})
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	jwk, err := getPublicJWKfromKeyResponse(keyResponse)
	if err != nil {
		return fmt.Errorf("failed to get JWK from key response: %w", err)
	}

	rsaPublicKey, err := getRSAPublicKeyfromJWK(jwk)
	if err != nil {
		return fmt.Errorf("failed to get RSA public key from JWK: %w", err)
	}

	return rsaPublicKey
}

func (s *Signer) GetPublicJWKSet(ctx context.Context) (jwk.Set, error) {
	listKeyPropertiesVersionPager := s.client.NewListKeyPropertiesVersionsPager(s.keyName, &azkeys.ListKeyPropertiesVersionsOptions{})

	keyVersions := []string{}
	for listKeyPropertiesVersionPager.More() {
		res, err := listKeyPropertiesVersionPager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get key properties versions: %w", err)
		}

		for _, key := range res.Value {
			if key == nil ||
				key.Attributes == nil ||
				key.Attributes.Expires == nil ||
				key.Attributes.Enabled == nil {
				continue
			}

			if time.Now().After(*key.Attributes.Expires) {
				continue
			}

			if !*key.Attributes.Enabled {
				continue
			}

			keyVersions = append(keyVersions, key.KID.Version())
		}
	}

	if len(keyVersions) == 0 {
		return nil, fmt.Errorf("no enabled key versions found")
	}

	jwkSet := jwk.NewSet()
	for _, keyVersion := range keyVersions {
		keyResponse, err := s.client.GetKey(s.ctx, s.keyName, keyVersion, &azkeys.GetKeyOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get key: %w", err)
		}

		pubKey, err := getPublicJWKfromKeyResponse(keyResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to get JWK from key response: %w", err)
		}

		jwkSet.AddKey(pubKey)
	}

	return jwkSet, nil
}

func (s *Signer) GetLatestKeyID(ctx context.Context) (string, error) {
	res, err := s.client.GetKey(s.ctx, s.keyName, useLatestKeyVersion, &azkeys.GetKeyOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get key: %w", err)
	}

	if res.Key.KID == nil {
		return "", fmt.Errorf("key missing KID")
	}

	if res.Key.KID.Version() == "" {
		return "", fmt.Errorf("key version missing")
	}

	return res.Key.KID.Version(), nil
}

func (s *Signer) getSignatureAlgorithm(opts crypto.SignerOpts) (*azkeys.SignatureAlgorithm, error) {
	switch opts {
	case crypto.SHA256:
		return to.Ptr(azkeys.SignatureAlgorithmRS256), nil
	}
	return nil, fmt.Errorf("unsupported signature algorithm: %s", opts)
}

func getPublicJWKfromKeyResponse(keyResponse azkeys.GetKeyResponse) (jwk.Key, error) {
	jsonKeyBytes, err := keyResponse.Key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	parsedJwk, err := jwk.ParseKey(jsonKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	pubKey, err := parsedJwk.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from JWK: %w", err)
	}

	err = pubKey.Set(jwk.KeyIDKey, keyResponse.Key.KID.Version())
	if err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	err = pubKey.Remove(jwk.KeyOpsKey)
	if err != nil {
		return nil, fmt.Errorf("failed to remove key operations: %w", err)
	}

	return pubKey, nil
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
