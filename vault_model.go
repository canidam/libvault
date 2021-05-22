package libvault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// client defines the minimal functions set for a Vault client
type client interface {
	Read(secretPath string) (map[string]string, error)
	LookupToken() error

	token() string
}

// auth performs a login and returns a clientToken and an error
type auth interface {
	Login(vc *VaultClient) (string, error)
}

type Option func(vc *VaultClient) error

type Approle struct {
	roleId   string
	secretId string
}

func (a Approle) Login(vc *VaultClient) (string, error) {
	jsonData := strings.NewReader(`{
					"role_id": "` + a.roleId + `", 
					"secret_id": "` + a.secretId + `"
				}`)

	r, _ := vc.newRequest("POST", ApproleLoginPath, jsonData)
	resp, err := vc.do(r)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("login failed: %d", resp.StatusCode)
	}

	var loginResp vaultLoginResp
	_ = parseJson(resp.Body, &loginResp)
	return loginResp.token(), nil
}

func SetVaultAddr(addr string) Option {
	return func(v *VaultClient) error {
		v.addr = addr
		return nil
	}
}

// SetToken configure the vault token to use when communicating with the server
func SetToken(token string) Option {
	return func(vc *VaultClient) error {
		if token == "" {
			return fmt.Errorf(ErrTokenMissing)
		}
		vc.clientToken = token
		return nil
	}
}

// UseApprole configures the client with the Approle auth method. Enabling this option
// will read the VAULT_ROLE_ID and VAULT_SECRET_ID from environment vars, and use them
// for Login()
func UseApprole() Option {
	return func(vc *VaultClient) error {
		a := Approle{
			os.Getenv("VAULT_ROLE_ID"),
			os.Getenv("VAULT_SECRET_ID"),
		}
		if a.roleId == "" {
			return fmt.Errorf("VAULT_ROLE_ID environment variable is not set, and expected to be")
		} else if a.secretId == "" {
			return fmt.Errorf("VAULT_SECRET_ID environment variable is not set, and expected to be")
		}
		vc.auth = a
		return nil
	}
}

// ProvideApprole allows to inject Approle struct to the client. Use this if you want
// to provide the roleId and secretId from outside, and not getting them from the environment vars.
func ProvideApprole(a Approle) Option {
	return func(vc *VaultClient) error {
		if a.roleId == "" || a.secretId == "" {
			return fmt.Errorf("roleId (%s) and secretId (%s) are both required and can not be empty",
				a.roleId, a.secretId)
		}
		vc.auth = a
		return nil
	}
}

// SetRootCA config the client with specific RootCAs to trust.
// Use this when you work with a vault server that uses self-signed certificates.
func SetRootCA(cp *x509.CertPool) Option {
	return func(vc *VaultClient) error {
		tlsCfg := &tls.Config{RootCAs: cp}
		vc.httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		return nil
	}
}

type vaultSecretResp struct {
	ResponseData struct {
		Data     map[string]string `json:"data"`
		Metadata struct {
			CreatedTime  string `json:"created_time"`
			DeletionTime string `json:"deleted_time"`
			Version      int    `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
	RequestID string `json:"request_id"`
}

func (vr *vaultSecretResp) Secrets() map[string]string {
	return vr.ResponseData.Data
}

type vaultLoginResp struct {
	LoginAuth struct {
		ClientToken string   `json:"client_token"`
		Accessor    string   `json:"accessor"`
		Policies    []string `json:"policies"`
	} `json:"auth"`
}

func (vl *vaultLoginResp) token() string {
	return vl.LoginAuth.ClientToken
}
