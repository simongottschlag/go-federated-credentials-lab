package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/alexflint/go-arg"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/simongottschlag/go-federated-credentials-lab/internal/azkeyssigner"
)

func main() {
	cfg, err := newConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate config: %v\n", err)
		os.Exit(1)
	}

	err = run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "application returned an error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		AdditionallyAllowedTenants: []string{"*"},
	})
	if err != nil {
		return fmt.Errorf("failed to get credentials: %w", err)
	}

	vaultURL := fmt.Sprintf("https://%s.vault.azure.net", cfg.KeyVaultName)
	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create a client: %w", err)
	}

	openidConfig := struct {
		JwksURI string `json:"jwks_uri"`
		Issuer  string `json:"issuer"`
	}{
		JwksURI: fmt.Sprintf("%s/.well-known/jwks.json", cfg.BlobServiceStaticEndpoint),
		Issuer:  cfg.BlobServiceStaticEndpoint,
	}

	openidConfigBytes, err := json.Marshal(openidConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal OpenID config: %w", err)
	}

	err = os.Mkdir(".tmp", 0755)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create a temporary directory: %w", err)
	}

	err = os.WriteFile(".tmp/openid-configuration", openidConfigBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write OpenID config: %w", err)
	}

	signer := azkeyssigner.New(ctx, client, cfg.KeyName)
	jwkSet, err := signer.GetPublicJWKSet(ctx)
	if err != nil {
		return fmt.Errorf("failed to get public JWK set: %w", err)
	}

	jwksBytes, err := json.Marshal(jwkSet)
	if err != nil {
		return fmt.Errorf("failed to marshal JWKS: %w", err)
	}

	err = os.WriteFile(".tmp/jwks.json", jwksBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JWKS: %w", err)
	}

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(openidConfig.Issuer).
		Subject(cfg.TokenSubject).
		Audience([]string{"api://AzureADTokenExchange"}).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(5 * time.Minute)).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build token: %w", err)
	}

	jwsProtectedHeaders := jws.NewHeaders()
	keyVersion, err := signer.GetLatestKeyID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest used key version: %w", err)
	}
	err = jwsProtectedHeaders.Set(jws.KeyIDKey, keyVersion)
	if err != nil {
		return fmt.Errorf("failed to set JWE protected header %q: %w", jws.KeyIDKey, err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), signer, jws.WithProtectedHeaders(jwsProtectedHeaders)))
	if err != nil {
		return fmt.Errorf("failed to sign token: %w", err)
	}

	fmt.Println(string(signed))

	return nil
}

type config struct {
	BlobServiceStaticEndpoint string `arg:"--blob-service-static-endpoint,required" help:"The static endpint of the storage account blob service."`
	KeyVaultName              string `arg:"--key-vault,required" help:"The name of the key vault."`
	KeyName                   string `arg:"--key-name,required" help:"The name of the key."`
	TokenSubject              string `arg:"--token-subject,required" help:"The subject of the token."`
}

func newConfig(args []string) (config, error) {
	cfg := config{}
	parser, err := arg.NewParser(arg.Config{
		Program:   "go-federated-credentials-lab",
		IgnoreEnv: true,
	}, &cfg)
	if err != nil {
		return config{}, err
	}

	err = parser.Parse(args)
	if err != nil {
		return config{}, err
	}

	return cfg, err
}
