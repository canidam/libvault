# libvault

[![libvault CI](https://github.com/canidam/libvault/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/canidam/libvault/actions/workflows/ci.yml) ![](https://img.shields.io/badge/Go-1.14%2B-informational) ![](https://img.shields.io/github/license/canidam/libvault) ![](https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Fgithub.com%2Fcanidam%2Flibvault)

A *lightweight* Hashicorp Vault client written in Go, with no dependencies.
It aims to provide an *intuitive, simple API* that is easy to use. Just like with the CLI.

Using the module, you currently can only *read* secrets from a Vault engine. This is an *ongoing project*,
feel free to open FRs, PRs or issues.

## Features

- Supported [Auth Methods](https://www.vaultproject.io/docs/auth):
    - Tokens
    - AppRole
    

- Supported [Secrets Engines](https://www.vaultproject.io/docs/secrets):
    - [KV v2.0](https://www.vaultproject.io/docs/secrets/kv/kv-v2)
    

- Support self-signed CA certificates
- The secrets are consumed using environment variables. You **should** set them before initializing the client.


## Installation
```bash
go get -v github.com/canidam/libvault
```

## Usage
```go
package main

import (
	"fmt"
	"github.com/canidam/libvault"
	"os"
)

func main() {
	//
	// Example using Token
	//
	
	// If env var is not set
	os.Setenv("VAULT_TOKEN", "my_token")

	tokenClient, err := libvault.NewClient(SetVaultAddr("http://localhost:8200"))
	if err != nil {
		// handle error
	}

	var secret_path = "/my.secrets"
	secretsUsingToken, err := tokenClient.Read(secret_path)
	if err != nil {
		// handle error
	}

	// secrets is of type map[string]string
	for k, v := range secretsUsingToken {
		fmt.Printf("key %s, secret %s\n", k, v)
	}
	
	//
	// Example using AppRole
	//
	
	// If env var is not set
	os.Setenv("VAULT_ROLE_ID", "my_role_id")	
	os.Setenv("VAULT_SECRET_ID", "my_secret_id")	
	os.Setenv("VAULT_ADDR", "http://localhost:8200")
	
	approleClient, err := libvault.NewClient(UseApprole())
	if err != nil { 
		// handle error
	}
        
	secretsUsingApprole, err := approleClient.Read(secret_path)
	if err != nil {
		// handle error
	}
  
	// secrets is of type map[string]string
	for k, v := range secretsUsingApprole {
		fmt.Printf("key %s, secret %s\n", k, v)
	}
}
```
## Documentation
Can be found [here](docs/DOCS.md)

## Tests
Checkout the project and run
```bash
go test -v ./...
```

`testdata/` is a special directory containing raw data for unit-tests.

`tests/` includes scripts (and it's own README) for starting a dev Vault server for development.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

If you'd like to contribute, please fork the repository and make changes as you'd like. Pull requests are warmly welcome.
Please make sure to update tests as appropriate.


## Roadmap
TBD

## License
[GPLv3.0](https://choosealicense.com/licenses/gpl-3.0/)
