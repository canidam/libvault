Until I have a stable version with a published documentation, here are the docs of this library:

```go
package libvault // import "github.com/canidam/libvault"


CONSTANTS

const (
        ApproleLoginPath = "/v1/auth/approle/login"
        TokenLookupPath  = "/v1/auth/token/lookup"
        DEFAULT_TIMEOUT  = 10
)

TYPES

type Approle struct {
        // Has unexported fields.
}

func (a Approle) Login(vc *VaultClient) (string, error)

type Option func(vc *VaultClient) error

func SetRootCA(cp *x509.CertPool) Option

func SetTransport(t *http.Transport) Option

func SetVaultAddr(addr string) Option

func UseApprole() Option

type VaultClient struct {
        // Has unexported fields.
}

func NewClient(opts ...func(v *VaultClient) error) (*VaultClient, error)
    NewClient creates a new Vault client. The default client is a valid one. You
    can configure it using functional options. Check the vault_test.go file for
    examples.

func (c *VaultClient) LookupToken() error

func (c *VaultClient) Read(secretPath string) (map[string]string, error)
    Read reads a single secret path from the Vault

func (c *VaultClient) ReadMany(secretsPaths []string) (map[string]string, error)
    ReadMany reads all the secretsPaths defined, returning a single map
    containing all the secrets. If a secret key exists in more than a single
    path, the secret return is from the last path specified.

func (c *VaultClient) String() string
```