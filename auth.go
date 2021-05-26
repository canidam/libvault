package libvault

import (
	"fmt"
	"os"
	"strings"
)

const (
	ApproleLoginPath = "/v1/auth/approle/login"
)

// auth provides a login and returns a clientToken and an error
type auth interface {
	Login(vc *VaultClient) (string, error)
}

type loginResp struct {
	LoginAuth struct {
		ClientToken string   `json:"client_token"`
		Accessor    string   `json:"accessor"`
		Policies    []string `json:"policies"`
	} `json:"auth"`
}

func (vl *loginResp) token() string {
	return vl.LoginAuth.ClientToken
}

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

	var lr loginResp
	_ = parseJson(resp.Body, &lr)
	return lr.token(), nil
}

// UseApprole configures the client with the Approle auth method. Enabling this option
// will read the VAULT_ROLE_ID and VAULT_SECRET_ID from environment vars
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

// ProvideApprole allows to inject Approle object to the client. Use this if you want
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

/*
TODO: 	userpass,
		aws
*/
