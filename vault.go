package libvault

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	ApproleLoginPath = "/v1/auth/approle/login"
	TokenLookupPath  = "/v1/auth/token/lookup"
	DEFAULT_TIMEOUT  = 10
)

type VaultClient struct {
	httpClient http.Client
	auth       auth

	addr        string
	clientToken string
	accessor    string
}

func (c *VaultClient) token() string {
	return c.clientToken
}

func (c *VaultClient) getRequest(secretPath string) (*http.Request, error) {
	var pathPrefix = "/v1/secret/data"
	path := fmt.Sprintf("%s%s", pathPrefix, secretPath)
	return c.newRequest("GET", path, nil)
}

func (c *VaultClient) String() string {
	return fmt.Sprintf("addr: %s, accessor: %s", c.addr, c.accessor)
}

func (c *VaultClient) do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

func (c *VaultClient) LookupToken() error {
	jsonData := strings.NewReader(`{
					"clientToken": "` + c.token() + `"
				}`)

	req, _ := c.newRequest("POST", TokenLookupPath, jsonData)
	resp, _ := c.httpClient.Do(req)

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to validate clientToken: code=%d %s", resp.StatusCode, vaultErrorMsg(resp.Body))
	}

	return nil
}

func (c *VaultClient) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	urlPath := fmt.Sprintf("%s%s", c.addr, path)
	req, err := http.NewRequest(method, urlPath, body)
	if err == nil {
		req.Header.Set("X-Vault-Token", c.token())
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	return req, err
}

func newClient(options ...func(v *VaultClient) error) (*VaultClient, error) {
	// Initialize default client
	vc := VaultClient{
		httpClient: http.Client{
			Timeout: time.Second * time.Duration(DEFAULT_TIMEOUT),
		},
		addr:        getEnv("VAULT_ADDR", "http://localhost:8200"),
		clientToken: getEnv("VAULT_TOKEN", ""),
	}

	// Apply client options
	for _, option := range options {
		if err := option(&vc); err != nil {
			return nil, fmt.Errorf("failed to initialize Vault client: %s", err)
		}
	}

	// Login to Vault
	if vc.auth != nil {
		token, err := vc.auth.Login(&vc)
		if err != nil {
			return nil, fmt.Errorf("failed to login with the authentication method provided %T: %s", vc.auth, err)
		}
		vc.clientToken = token
	}

	if vc.addr == "" {
		return nil, fmt.Errorf("vault address can't be an empty string")
	}

	return &vc, nil
}

// NewClient creates a new Vault client. The default client is a valid one. You can configure it
// using functional options. Check the vault_test.go file for examples.
func NewClient(opts ...func(v *VaultClient) error) (*VaultClient, error) {
	return newClient(opts...)
}

// Read reads a single secret path from the Vault
func (c *VaultClient) Read(secretPath string) (map[string]string, error) {
	req, _ := c.getRequest(secretPath)
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("request for %s: %s", req.URL, err)
	} else if resp.StatusCode != 200 {

		switch resp.StatusCode {
		case 403:
			return nil, fmt.Errorf("%d: Authorization error. Check your clientToken", resp.StatusCode)
		case 404:
			return nil, fmt.Errorf("%d: Secret not found: %s", resp.StatusCode, req.URL)
		default:
			return nil, fmt.Errorf("%d: Unknown error", resp.StatusCode)
		}
	}

	var vaultResponse vaultSecretResp
	_ = parseJson(resp.Body, &vaultResponse)
	return vaultResponse.Secrets(), err
}

// ReadMany reads all the secretsPaths defined, returning a single map containing all the secrets.
// If a secret key exists in more than a single path, the secret return is from the last path specified.
func (c *VaultClient) ReadMany(secretsPaths []string) (map[string]string, error) {
	var secretsMap = make(map[string]string)

	for _, secret := range secretsPaths {
		retMap, err := c.Read(secret)
		if err != nil {
			return nil, err
		}
		for k, v := range retMap {
			secretsMap[k] = v
		}
	}
	return secretsMap, nil
}
