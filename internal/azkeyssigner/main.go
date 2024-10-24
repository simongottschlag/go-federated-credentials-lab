package azkeyssigner

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
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
	panic("not implemented")
}

func (s *Signer) getSignatureAlgorithm(opts crypto.SignerOpts) (*azkeys.SignatureAlgorithm, error) {
	switch opts {
	case crypto.SHA256:
		return to.Ptr(azkeys.SignatureAlgorithmRS256), nil
	}
	return nil, fmt.Errorf("unsupported signature algorithm: %s", opts)
}
