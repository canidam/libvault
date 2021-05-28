package libvault

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	ApproleLoginPath = "/v1/auth/approle/login"
	AwsroleLoginPath = "/v1/auth/aws/login"
)

// auth provides a login and returns a clientToken and an error
type auth interface {
	LoginPayload() io.Reader
	LoginEndpoint() string
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

func (a Approle) LoginEndpoint() string {
	return ApproleLoginPath
}

func (a Approle) LoginPayload() io.Reader {
	return strings.NewReader(`{
					"role_id": "` + a.roleId + `", 
					"secret_id": "` + a.secretId + `"
				}`)
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

type Awsrole struct {
	role  string
	pkcs7 string
	nonce string
}

func (a Awsrole) LoginEndpoint() string {
	return AwsroleLoginPath
}

func (a Awsrole) LoginPayload() io.Reader {
	return strings.NewReader(`{
					"role": "` + a.role + `", 
					"pkcs7": "` + a.pkcs7 + `",
					"nonce": "` + a.nonce + `"
				}`)
}

// UseAwsrole configures the client with the Awsrole auth method.
// It reads the VAULT_ROLE, VAULT_PKCS7 and VAULT_NONCE from environment vars
func UseAwsrole() Option {
	return func(vc *VaultClient) error {
		a := Awsrole{
			os.Getenv("VAULT_AWS_ROLE"),
			os.Getenv("VAULT_AWS_PKCS7"),
			os.Getenv("VAULT_AWS_NONCE"),
		}
		if a.role == "" {
			return fmt.Errorf("VAULT_AWS_ROLE environment variable is not set, and expected to be")
		} else if a.pkcs7 == "" {
			return fmt.Errorf("VAULT_AWS_PKCS7 environment variable is not set, and expected to be")
		} else if a.nonce == "" {
			return fmt.Errorf("VAULT_AWS_NONCE environment variable is not set, and expected to be")
		}
		vc.auth = a
		return nil
	}
}

// ProvideAwsrole allows to inject Awsrole object to the client. Use this if you want
// to provide the struct fields from outside, and not getting them from the environment vars.
func ProvideAwsrole(a Awsrole) Option {
	return func(vc *VaultClient) error {
		if a.role == "" || a.pkcs7 == "" || a.nonce == "" {
			return fmt.Errorf("role (%s), pkcs7 (%s) and nonce (%s) are required and can not be empty",
				a.role, a.pkcs7, a.nonce)
		}
		vc.auth = a
		return nil
	}
}

/*
TODO: 	userpass
*/
