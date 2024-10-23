// Original: https://github.com/AzureCR/go-jwt-azure
//
// MIT License
//
// Copyright (c) 2021 Shiwei Zhang
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"context"
	"crypto"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type key struct {
	client     *azkeys.Client
	ctx        context.Context
	keyName    string
	keyVersion string
}

func newKey(ctx context.Context, client *azkeys.Client, keyName string, keyVersion string) (*key, error) {
	return &key{
		client:     client,
		ctx:        ctx,
		keyName:    keyName,
		keyVersion: keyVersion,
	}, nil
}

func (k *key) Sign(algorithm azkeys.SignatureAlgorithm, message []byte) ([]byte, error) {
	digest, err := computeHash(algorithm, message)
	if err != nil {
		return nil, err
	}
	return k.SignDigest(algorithm, digest)
}

func (k *key) SignDigest(algorithm azkeys.SignatureAlgorithm, digest []byte) ([]byte, error) {
	res, err := k.client.Sign(
		k.ctx,
		k.keyName,
		k.keyVersion,
		azkeys.SignParameters{
			Algorithm: &algorithm,
			Value:     digest,
		},
		&azkeys.SignOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to sign the digest: %w", err)
	}

	if res.KID == nil || res.KID.Version() != k.keyVersion {
		return nil, fmt.Errorf("unexpected key version in the response")
	}

	if res.Result == nil {
		return nil, fmt.Errorf("missing signature result")
	}

	return res.Result, nil
}

func (k *key) Verify(algorithm azkeys.SignatureAlgorithm, message, signature []byte) error {
	digest, err := computeHash(algorithm, message)
	if err != nil {
		return err
	}
	return k.VerifyDigest(algorithm, digest, signature)
}

func (k *key) VerifyDigest(algorithm azkeys.SignatureAlgorithm, digest, signature []byte) error {
	res, err := k.client.Verify(
		k.ctx,
		k.keyName,
		k.keyVersion,
		azkeys.VerifyParameters{
			Algorithm: &algorithm,
			Digest:    digest,
			Signature: signature,
		},
		&azkeys.VerifyOptions{})
	if err != nil {
		return fmt.Errorf("failed to verify the signature: %w", err)
	}

	if res.Value == nil {
		return fmt.Errorf("missing verification result")
	}

	if valid := *res.Value; !valid {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

var hashAlgorithms = map[azkeys.SignatureAlgorithm]crypto.Hash{
	azkeys.SignatureAlgorithmRS256: crypto.SHA256,
}

func computeHash(algorithm azkeys.SignatureAlgorithm, message []byte) ([]byte, error) {
	hash, ok := hashAlgorithms[algorithm]

	if !ok {
		return nil, fmt.Errorf("unsupported algorithm: %v", algorithm)
	}

	if !hash.Available() {
		return nil, fmt.Errorf("hash algorithm not available: %v", hash)
	}

	h := hash.New()
	_, err := h.Write(message)
	if err != nil {
		return nil, fmt.Errorf("failed to write the message: %w", err)
	}

	return h.Sum(nil), nil
}

var (
	signingMethodRS256 = &signingMethod{algorithm: azkeys.SignatureAlgorithmRS256}
)

type signingMethod struct {
	algorithm azkeys.SignatureAlgorithm
}

func (m *signingMethod) Alg() string {
	return string(m.algorithm)
}

func (m *signingMethod) Sign(signingString string, inputKey interface{}) ([]byte, error) {
	k, ok := inputKey.(*key)
	if !ok {
		return nil, fmt.Errorf("invalid key type")
	}

	sig, err := k.Sign(m.algorithm, []byte(signingString))
	if err != nil {
		return nil, fmt.Errorf("failed to sign the string: %w", err)
	}

	return sig, nil
}

func (m *signingMethod) Verify(signingString string, sig []byte, inputKey interface{}) error {
	k, ok := inputKey.(*key)
	if !ok {
		return fmt.Errorf("invalid key type")
	}

	err := k.Verify(m.algorithm, []byte(signingString), sig)
	if err != nil {
		return fmt.Errorf("failed to verify the signature: %w", err)
	}

	return nil
}
