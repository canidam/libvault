package libvault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	TokenLookupPath = "/v1/auth/token/lookup"
	DefaultTimeout  = 10

	ErrAddrMissing  = "vault address is missing"
	ErrTokenMissing = "vault token is missing"
	ErrEmptyToken   = "vault parsed token is empty"
	ErrSecretParse  = "failed to parse secret"
	Err403Auth      = "Authorization error. Check your clientToken."
	Err404NotFound  = "Secret not found"
	ErrUnknown      = "Unknown error"
)

// client defines the minimal functions set for a Vault client
type client interface {
	Read(secretPath string) (map[string]string, error)
	LookupToken() error

	token() string
}

type Option func(vc *VaultClient) error

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

func (c *VaultClient) do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

func (c *VaultClient) getRequest(secretPath string) (*http.Request, error) {
	var pathPrefix = "/v1/secret/data"
	path := fmt.Sprintf("%s%s", pathPrefix, secretPath)
	return c.newRequest("GET", path, nil)
}

func (c *VaultClient) String() string {
	return fmt.Sprintf("addr: %s, accessor: %s", c.addr, c.accessor)
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

// login authenticates with the provided backend, and configures the token of the client
func (c *VaultClient) login(authMethod auth) error {
	jsonData := authMethod.LoginPayload()
	r, _ := c.newRequest("POST", authMethod.LoginEndpoint(), jsonData)
	resp, err := c.do(r)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("login failed: %d", resp.StatusCode)
	}

	var lr loginResp
	_ = parseJson(resp.Body, &lr)

	token := lr.token()
	if token == "" {
		return errors.New(ErrEmptyToken)
	}
	c.clientToken = token
	return nil
}

func newClient(options ...func(v *VaultClient) error) (*VaultClient, error) {
	// Initialize default client
	vc := VaultClient{
		httpClient: http.Client{
			Timeout: time.Second * time.Duration(DefaultTimeout),
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
		err := vc.login(vc.auth)
		if err != nil {
			return nil, fmt.Errorf("failed to login with the authentication method provided %T: %s", vc.auth, err)
		}
	}

	if vc.addr == "" {
		return nil, errors.New(ErrAddrMissing)
	}

	if vc.clientToken == "" {
		return nil, errors.New(ErrTokenMissing)
	}

	return &vc, nil
}

// NewClient creates a new Vault client. The default client is a valid one. You can configure it
// using functional options. Check the vault_test.go file for examples.
func NewClient(opts ...func(v *VaultClient) error) (*VaultClient, error) {
	return newClient(opts...)
}

// SetVaultAddr configures the vault server address of the client
func SetVaultAddr(addr string) Option {
	return func(v *VaultClient) error {
		v.addr = addr
		return nil
	}
}

// SetToken configures the vault token to use when communicating with the server
func SetToken(token string) Option {
	return func(vc *VaultClient) error {
		if token == "" {
			return errors.New(ErrTokenMissing)
		}
		vc.clientToken = token
		return nil
	}
}

// SetRootCA configures the client with specific RootCAs to trust.
// Use this when you work with a vault server that uses self-signed certificates.
func SetRootCA(cp *x509.CertPool) Option {
	return func(vc *VaultClient) error {
		tlsCfg := &tls.Config{RootCAs: cp}
		vc.httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		return nil
	}
}

//
// Helpers
//

// parseSecret reads response from Vault, figuring out the (supported) secret engine backend
// and returns a Secret to the caller
func parseSecret(resp io.Reader) (Secret, error) {
	bodyBytes, _ := ioutil.ReadAll(resp)

	// KV Backend
	var kv kvSecretResp
	if err := parseJson(bytes.NewBuffer(bodyBytes), &kv); err != nil {
		return nil, err
	}
	if kv.RequestID != "" && len(kv.Secrets()) > 0 && kv.Version() != 0 {
		return kv, nil
	}

	// TODO: Handle other secret engine backends, e.g AWS
	return nil, errors.New(ErrSecretParse)
}

// parseJson extract json content from http.Response to a struct
func parseJson(resp io.Reader, responseStruct interface{}) error {
	bytesData, err := ioutil.ReadAll(resp)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytesData, responseStruct)
}

// getEnv returns value from the environment, or fallback if it isn't set
func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	} else {
		return fallback
	}
}

// vaultErrorMsg extracts the body content of a vault error
func vaultErrorMsg(resp io.ReadCloser) interface{} {
	var respData map[string]interface{}
	_ = parseJson(resp, &respData)
	if val, ok := respData["errors"]; ok {
		return val
	}
	return respData
}

//
// Public API
//

// LookupToken performs lookup on a token (mostly to validate it)
func (c *VaultClient) LookupToken() error {
	jsonData := strings.NewReader(`{
					"clientToken": "` + c.token() + `"
				}`)

	req, _ := c.newRequest("POST", TokenLookupPath, jsonData)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate clientToken: err=%s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to validate clientToken: code=%d %s", resp.StatusCode, vaultErrorMsg(resp.Body))
	}

	return nil
}

// Read reads a single secret path from the Vault
func (c *VaultClient) Read(secretPath string) (map[string]string, error) {
	req, _ := c.getRequest(secretPath)
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("request for %s: %s", req.URL, err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {

		switch resp.StatusCode {
		case 403:
			return nil, fmt.Errorf("%d: %s %s", resp.StatusCode, Err403Auth, vaultErrorMsg(resp.Body))
		case 404:
			return nil, fmt.Errorf("%d: %s: %s", resp.StatusCode, Err404NotFound, req.URL)
		default:
			return nil, fmt.Errorf("%d: %s. %s", resp.StatusCode, ErrUnknown, vaultErrorMsg(resp.Body))
		}
	}

	var s Secret
	s, err = parseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	return s.Secrets(), err
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
