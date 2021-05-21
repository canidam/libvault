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

func UseApprole() Option {
	return func(v *VaultClient) error {
		a := Approle{
			os.Getenv("VAULT_ROLE_ID"),
			os.Getenv("VAULT_SECRET_ID"),
		}
		v.auth = a
		return nil
	}
}

func SetTransport(t *http.Transport) Option {
	return func(v *VaultClient) error {
		v.httpClient.Transport = t
		return nil
	}
}

func SetRootCA(cp *x509.CertPool) Option {
	return func(v *VaultClient) error {
		tlsCfg := &tls.Config{RootCAs: cp}
		v.httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
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
