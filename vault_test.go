package libvault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const (
	caCertPath     = "testdata/certs/ca.crt"
	serverCertPath = "testdata/certs/server.crt"
	serverKeyPath  = "testdata/certs/server.key"

	VaultRoleId   = "319418d1-7a8b-2da6-46c3-e0301f3ce02a"
	VaultSecretId = "ce5e446d-3a60-54b6-5996-78b8f04ec03b"

	VaultAwsRole  = "dev-role"
	VaultAwsPkcs7 = "ZxZxSCQmGIGIqGSIbAqCAMIAGC" // shorten for readability
	VaultAwsNonce = "mysupersecretnonce"

	ApproleLoginResponse = "approleLoginResponse.json"
	AwsroleLoginResponse = "awsroleLoginResponse.json"
	LookupResponse       = "lookupResponse.json"
	Data1Response        = "data1.json"
	Data2Response        = "data2.json"
)

var (
	tokenClient   client
	approleClient client
	certPool      *x509.CertPool
)

func readFixture(filename string) []byte {
	bytes, err := ioutil.ReadFile("testdata/" + filename)
	if err != nil {
		panic(err)
	}
	return bytes
}

func respondWithJson(w http.ResponseWriter, code int, jsonPayload []byte) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err := w.Write(jsonPayload)
	return err
}

func setup(enableTLS bool) (*httptest.Server, *http.ServeMux) {
	mux := http.NewServeMux()
	ts := httptest.NewUnstartedServer(mux)

	if enableTLS {
		if certPool == nil {
			// initialize certPool for client usage
			certPool = x509.NewCertPool()
			caCert, _ := ioutil.ReadFile(caCertPath)
			ok := certPool.AppendCertsFromPEM(caCert)
			if !ok {
				panic("failed to add caCert to certPool")
			}
		}

		cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
		if err != nil {
			panic(err)
		}
		ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		ts.StartTLS()

	} else {
		ts.Start()
	}

	return ts, mux
}

func TestClientStringRep(t *testing.T) {
	Client, err := NewClient()
	if err != nil {
		t.Error(err)
		return
	}

	Client.accessor = "dummy"
	if Client.String() != "addr: http://localhost:8200, accessor: dummy" {
		t.Error("string representation is wrong")
	}
}

func TestNewClientDefaults(t *testing.T) {
	ts, mux := setup(false)
	defer ts.Close()

	mux.HandleFunc(TokenLookupPath, func(w http.ResponseWriter, r *http.Request) {
		testRequestIsValid(t, "POST", r)
		if err := respondWithJson(w, http.StatusOK, readFixture(LookupResponse)); err != nil {
			t.Error(err)
		}
	})

	var err error
	if tokenClient, err = NewClient(SetVaultAddr(ts.URL)); err != nil {
		t.Error(err)
		return
	}

	if tokenClient == nil {
		t.Error("failed to create NewClient with defaults")
		return
	}

	if err = tokenClient.LookupToken(); err != nil {
		t.Error(err)
	}
}

func TestInvalidParamsNewClient(t *testing.T) {
	// Invalid Vault Address
	invalidAddrClient, err := NewClient(SetVaultAddr(""))
	if invalidAddrClient != nil || err == nil {
		t.Error("expecting nil client and non-nil error")
		return
	}

	if !strings.Contains(err.Error(), ErrAddrMissing) {
		t.Errorf("expecting %s as part of error: %s", ErrAddrMissing, err.Error())
	}

	// Missing token
	invalidTokenClient, err := NewClient(SetToken(""))
	if invalidTokenClient != nil || err == nil {
		t.Errorf("expecting nil client (%s) and non-nil error (%s)", invalidTokenClient, err)
		return
	}
	if !strings.Contains(err.Error(), ErrTokenMissing) {
		t.Errorf("expecting %s as part of error: %s", ErrTokenMissing, err.Error())
	}
}

func TestNewClientSetToken(t *testing.T) {
	ts, mux := setup(false)
	defer ts.Close()

	mux.HandleFunc(TokenLookupPath, func(w http.ResponseWriter, r *http.Request) {
		testRequestIsValid(t, "POST", r)
		if err := respondWithJson(w, http.StatusOK, readFixture(LookupResponse)); err != nil {
			t.Error(err)
		}
	})

	testToken := "fake-token"
	setTokenClient, err := NewClient(SetVaultAddr(ts.URL), SetToken(testToken))
	if err != nil {
		t.Error(err)
	}
	if setTokenClient.token() != testToken {
		t.Errorf("token mismatch. expected=%s, actual=%s", testToken, setTokenClient.token())
	}
}

func TestNewClientWithAppRole(t *testing.T) {
	ts, mux := setup(true)
	defer ts.Close()

	mux.HandleFunc(ApproleLoginPath, func(w http.ResponseWriter, r *http.Request) {
		_ = respondWithJson(w, http.StatusOK, readFixture(ApproleLoginResponse))
	})

	var err error
	approleClient, err = NewClient(SetVaultAddr(ts.URL), SetRootCA(certPool), UseApprole())
	if err != nil {
		t.Error(err)
		return
	}
	if approleClient != nil && approleClient.token() == "" {
		t.Error("clientToken is empty; failed to connect with NewClient with AppRole method")
		return
	}
}

func TestNewClientProvideAppRole(t *testing.T) {
	ts, mux := setup(true)
	defer ts.Close()

	mux.HandleFunc(ApproleLoginPath, func(w http.ResponseWriter, r *http.Request) {
		_ = respondWithJson(w, http.StatusOK, readFixture(ApproleLoginResponse))
	})

	approleClient, err := NewClient(SetVaultAddr(ts.URL), SetRootCA(certPool), ProvideApprole(Approle{
		roleId:   VaultRoleId,
		secretId: VaultSecretId,
	}))
	if err != nil {
		t.Error(err)
		return
	}
	if approleClient != nil && approleClient.token() == "" {
		t.Error("clientToken is empty")
		return
	}
}

func TestNewClientWithAwsRole(t *testing.T) {
	ts, mux := setup(true)
	defer ts.Close()

	mux.HandleFunc(AwsroleLoginPath, func(w http.ResponseWriter, r *http.Request) {
		_ = respondWithJson(w, http.StatusOK, readFixture(AwsroleLoginResponse))
	})

	awsClient, err := NewClient(SetVaultAddr(ts.URL), SetRootCA(certPool), UseAwsrole())
	if err != nil {
		t.Error(err)
		return
	}
	if awsClient != nil && awsClient.token() == "" {
		t.Error("clientToken is empty")
		return
	}
}

func TestNewClientProvideAwsRole(t *testing.T) {
	ts, mux := setup(true)
	defer ts.Close()

	mux.HandleFunc(AwsroleLoginPath, func(w http.ResponseWriter, r *http.Request) {
		_ = respondWithJson(w, http.StatusOK, readFixture(AwsroleLoginResponse))
	})

	awsClient, err := NewClient(SetVaultAddr(ts.URL), SetRootCA(certPool), ProvideAwsrole(Awsrole{
		role:  VaultAwsRole,
		pkcs7: VaultAwsPkcs7,
		nonce: VaultAwsNonce,
	}))

	if err != nil {
		t.Error(err)
		return
	}
	if awsClient != nil && awsClient.token() == "" {
		t.Error("clientToken is empty")
		return
	}
}

func testRequestIsValid(t *testing.T, expectedMethod string, r *http.Request) {
	t.Helper()
	if r.Method != expectedMethod {
		t.Errorf("expecting %s method", expectedMethod)
	}
	if _, ok := r.Header["X-Vault-Token"]; !ok {
		t.Error("missing vault token in request")
	}
}

func TestReads(t *testing.T) {
	ts, mux := setup(true)
	defer ts.Close()

	// login happens here
	mux.HandleFunc(ApproleLoginPath, func(w http.ResponseWriter, r *http.Request) {
		_ = respondWithJson(w, http.StatusOK, readFixture(ApproleLoginResponse))
	})
	// fetch secrets here
	mux.HandleFunc("/v1/secret/data/data1", func(w http.ResponseWriter, r *http.Request) {
		testRequestIsValid(t, "GET", r)
		err := respondWithJson(w, http.StatusOK, readFixture(Data1Response))
		if err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("/v1/secret/data/data2", func(w http.ResponseWriter, r *http.Request) {
		testRequestIsValid(t, "GET", r)
		err := respondWithJson(w, http.StatusOK, readFixture(Data2Response))
		if err != nil {
			t.Error(err)
		}
	})

	approleClient, _ = NewClient(SetVaultAddr(ts.URL), SetRootCA(certPool), UseApprole())
	if approleClient == nil || approleClient.token() == "" {
		t.Error("approleClient is not initialized")
		return
	}

	cases := []struct {
		path     string
		expected map[string]string
	}{
		{"/data1", map[string]string{"mysecret": "supersecret"}},
		{"/data2", map[string]string{"secondsupersecret": "updatedsecret", "anothersecret": "hollymolly"}},
	}

	t.Run("Read", func(t *testing.T) {
		for _, _case := range cases {
			resp, err := approleClient.Read(_case.path)
			if err != nil {
				t.Error(err)
			} else {
				if fmt.Sprint(resp) != fmt.Sprint(_case.expected) {
					t.Errorf("%s != %s", resp, _case.expected)
				}
			}
		}
	})

	t.Run("ReadMany", func(t *testing.T) {
		var paths []string
		var retMap = make(map[string]string)

		for _, c := range cases {
			paths = append(paths, c.path)
			for k, v := range c.expected {
				retMap[k] = v
			}
		}

		resp, err := approleClient.(*VaultClient).ReadMany(paths)
		if err != nil {
			t.Error(err)
		} else {
			if fmt.Sprint(resp) != fmt.Sprint(retMap) {
				t.Errorf("%s != %s", resp, retMap)
			}
		}
	})
}

func TestReadErrors(t *testing.T) {
	ts, mux := setup(false)
	defer ts.Close()

	mux.HandleFunc("/v1/secret/data/403", func(w http.ResponseWriter, r *http.Request) {
		testRequestIsValid(t, "GET", r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		_, _ = w.Write([]byte("* permission denied"))
	})

	mux.HandleFunc("/v1/secret/data/404", func(w http.ResponseWriter, r *http.Request) {
		testRequestIsValid(t, "GET", r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte("* not found"))
	})

	mux.HandleFunc("/v1/secret/data/500", func(w http.ResponseWriter, r *http.Request) {
		testRequestIsValid(t, "GET", r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		_, _ = w.Write([]byte("* unknown error"))
	})

	Client, err := NewClient(SetVaultAddr(ts.URL))
	if err != nil {
		t.Error(err)
		return
	}

	t.Run("403", func(t *testing.T) {
		sm, err := Client.Read("/403")
		if sm != nil {
			t.Errorf("expecting nil map")
		}
		if err == nil || !strings.Contains(err.Error(), Err403Auth) {
			t.Errorf("expecting 403, got %s", err)
		}
	})

	t.Run("404", func(t *testing.T) {
		sm, err := Client.Read("/404")
		if sm != nil {
			t.Errorf("expecting nil map")
		}
		if err == nil || !strings.Contains(err.Error(), Err404NotFound) {
			t.Errorf("expecting 404, got %s", err)
		}
	})

	t.Run("500", func(t *testing.T) {
		sm, err := Client.Read("/500")
		if sm != nil {
			t.Errorf("expecting nil map")
		}
		if err == nil || !strings.Contains(err.Error(), ErrUnknown) {
			t.Errorf("expecting 500, got %s", err)
		}
	})
}

func init() {
	// Tokens and Approle info is read from env variables.
	// This sets them up for the tests.
	_ = os.Setenv("VAULT_TOKEN", "root-token")
	_ = os.Setenv("VAULT_ROLE_ID", VaultRoleId)
	_ = os.Setenv("VAULT_SECRET_ID", VaultSecretId)

	// Awsrole
	_ = os.Setenv("VAULT_AWS_ROLE", VaultAwsRole)
	_ = os.Setenv("VAULT_AWS_PKCS7", VaultAwsPkcs7)
	_ = os.Setenv("VAULT_AWS_NONCE", VaultAwsNonce)

}
