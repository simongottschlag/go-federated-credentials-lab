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
	"github.com/golang-jwt/jwt/v5"
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

	res, err := client.GetKey(ctx, cfg.KeyName, "", nil)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	keyVersion := res.Key.KID.Version()
	if keyVersion == "" {
		return fmt.Errorf("missing key version")
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

	jwk := struct {
		Kty string `json:"kty"`
		E   string `json:"e"`
		N   string `json:"n"`
		Kid string `json:"kid"`
	}{}
	resJsonBytes, err := res.Key.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	err = json.Unmarshal(resJsonBytes, &jwk)
	if err != nil {
		return fmt.Errorf("failed to unmarshal key: %w", err)
	}

	jwk.Kid = keyVersion

	jwks := struct {
		Keys []struct {
			Kty string `json:"kty"`
			E   string `json:"e"`
			N   string `json:"n"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}{}

	jwks.Keys = append(jwks.Keys, jwk)

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return fmt.Errorf("failed to marshal JWKS: %w", err)
	}

	err = os.WriteFile(".tmp/jwks.json", jwksBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JWKS: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": openidConfig.Issuer,
		"sub": cfg.TokenSubject,
		"aud": "api://AzureADTokenExchange",
		"nbf": now.Unix(),
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(signingMethodRS256, claims)
	token.Header["kid"] = keyVersion

	key, err := newKey(ctx, client, "jwt-encryption", keyVersion)
	if err != nil {
		return fmt.Errorf("failed to create a key: %w", err)
	}

	serialized, err := token.SignedString(key)
	if err != nil {
		return fmt.Errorf("failed to sign token: %w", err)
	}

	fmt.Println(serialized)

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
