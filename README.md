# go-federated-credentials-lab

Lab to test things with federated credentials.

## Using the lab

- Create a keyvault
- Create key
- Create a storage account
- Enable static website on storage account
- Run it once and:
  - Upload `.tmp/openid-configuration` to `$web` in the folder `.well-known` and change the content type to `application/json`
  - Upload `.tmp/jwks.json` to to `$web` in the folder `.well-known`
- Create an application in Entra ID and add a federated credential with the issuer `https://storageaccountname.z1.web.core.windows.net` and subject `the-subject`
  - Save the client id and tenant id for usage in the last step
- Login with a user account that has access to the KeyVault using Azure CLI
- Extract a token
- Login using the federated credential

## Run

```shell
az login
TOKEN=$(go run ./... --blob-service-static-endpoint https://storageaccountname.z1.web.core.windows.net --key-vault key-vault-name --key-name key-name --token-subject the-subject)
az login --service-principal --username client-id --tenant tenant-id --allow-no-subscriptions --federated-token $TOKEN
```

## Created content

### Decoded token

```json
{
  "alg": "RS256",
  "kid": "key-version",
  "typ": "JWT"
}.{
  "aud": "api://AzureADTokenExchange",
  "exp": 1729722891,
  "iat": 1729722291,
  "iss": "https://storageaccountname.z1.web.core.windows.net",
  "nbf": 1729722291,
  "sub": "the-subject"
}.[Signature]
```

### jwks.json

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "n": "[...]",
      "kid": "key-version"
    }
  ]
}
```

### openid-configuration

```json
{
  "jwks_uri": "https://storageaccountname.z1.web.core.windows.net/.well-known/jwks.json",
  "issuer": "https://storageaccountname.z1.web.core.windows.net"
}
```
