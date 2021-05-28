Until I have a stable version with a published documentation, here are the docs of this library:

```go
package libvault // import "github.com/canidam/libvault"


CONSTANTS

const (
	ApproleLoginPath = "/v1/auth/approle/login"
	AwsroleLoginPath = "/v1/auth/aws/login"
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

TYPES

type Approle struct {
	// Has unexported fields.
}

func (a Approle) LoginEndpoint() string

func (a Approle) LoginPayload() io.Reader

type Awsrole struct {
	// Has unexported fields.
}

func (a Awsrole) LoginEndpoint() string

func (a Awsrole) LoginPayload() io.Reader

type Option func(vc *VaultClient) error

func ProvideApprole(a Approle) Option

ProvideApprole allows to inject Approle object to the client. Use this if
you want to provide the roleId and secretId from outside, and not getting
them from the environment vars.

func ProvideAwsrole(a Awsrole) Option

ProvideAwsrole allows to inject Awsrole object to the client. Use this if
you want to provide the struct fields from outside, and not getting them
from the environment vars.

func SetRootCA(cp *x509.CertPool) Option

SetRootCA configures the client with specific RootCAs to trust. Use this
when you work with a vault server that uses self-signed certificates.

func SetToken(token string) Option

SetToken configures the vault token to use when communicating with the
server

func SetVaultAddr(addr string) Option

SetVaultAddr configures the vault server address of the client

func UseApprole() Option

UseApprole configures the client with the Approle auth method. Enabling this
option will read the VAULT_ROLE_ID and VAULT_SECRET_ID from environment vars

func UseAwsrole() Option

UseAwsrole configures the client with the Awsrole auth method. It reads the
VAULT_ROLE, VAULT_PKCS7 and VAULT_NONCE from environment vars

type Secret interface {
	Secrets() map[string]string
}
Secret is the interface to fetch secrets from the secrets engine used

type VaultClient struct {
	// Has unexported fields.
}

func NewClient(opts ...func(v *VaultClient) error) (*VaultClient, error)

NewClient creates a new Vault client. The default client is a valid one. You
can configure it using functional options. Check the vault_test.go file for
examples.

func (c *VaultClient) LookupToken() error

LookupToken performs lookup on a token (mostly to validate it)

func (c *VaultClient) Read(secretPath string) (map[string]string, error)

Read reads a single secret path from the Vault

func (c *VaultClient) ReadMany(secretsPaths []string) (map[string]string, error)

ReadMany reads all the secretsPaths defined, returning a single map
containing all the secrets. If a secret key exists in more than a single
path, the secret return is from the last path specified.
```