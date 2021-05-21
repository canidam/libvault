package libvault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const (
	caCertPath     = "testdata/certs/ca.crt"
	serverCertPath = "testdata/certs/server.crt"
	serverKeyPath  = "testdata/certs/server.key"

	ApproleLoginResponse = "approleLoginResponse.json"
	LookupResponse       = "lookupResponse.json"
	Data1Response        = "data1.json"
)

var (
	tokenClient   Client
	approleClient Client
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

func respondWithError(w http.ResponseWriter, code int, err string) error {
	b := []byte(fmt.Sprintf(`{"error": "%s"}`, err))
	return respondWithJson(w, code, b)
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

func TestNewClientDefaults(t *testing.T) {
	ts, mux := setup(true)
	defer ts.Close()

	mux.HandleFunc(TokenLookupPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			_ = respondWithError(w, http.StatusMethodNotAllowed, "expecting Post method")
			return
		}
		if _, ok := r.Header["X-Vault-Token"]; !ok {
			_ = respondWithError(w, http.StatusBadRequest, "missing vault token in request")
			return
		}
		if err := respondWithJson(w, http.StatusOK, readFixture(LookupResponse)); err != nil {
			t.Error(err)
		}
	})

	var err error
	if tokenClient, err = NewClient(SetVaultAddr(ts.URL), SetRootCA(certPool)); err != nil {
		t.Error(err)
		return
	}

	if tokenClient == nil || tokenClient.token() == "" {
		t.Error("failed to create NewClient with defaults: token is nil")
		return
	}

	if err = tokenClient.LookupToken(); err != nil {
		t.Error(err)
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

func TestGetSecret(t *testing.T) {
	ts, mux := setup(true)
	defer ts.Close()

	// login happens here
	mux.HandleFunc(ApproleLoginPath, func(w http.ResponseWriter, r *http.Request) {
		_ = respondWithJson(w, http.StatusOK, readFixture(ApproleLoginResponse))
	})
	// fetch secrets here
	mux.HandleFunc("/v1/secret/data/data1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			_ = respondWithError(w, http.StatusMethodNotAllowed, "expecting Get method")
			return
		}
		if _, ok := r.Header["X-Vault-Token"]; !ok {
			_ = respondWithError(w, http.StatusBadRequest, "missing vault token in request")
			return
		}
		err := respondWithJson(w, http.StatusOK, readFixture(Data1Response))
		if err != nil {
			t.Error(err)
		}
	})

	approleClient, _ = NewClient(SetVaultAddr(ts.URL), SetRootCA(certPool), UseApprole())
	if approleClient.token() == "" {
		t.Error("approleClient is not initialized")
		return
	}

	cases := []struct {
		path     string
		expected map[string]string
	}{
		{"/data1", map[string]string{"mysecret": "supersecret"}},
	}

	for _, _case := range cases {
		t.Run(_case.path, func(t *testing.T) {
			resp, err := approleClient.Read(_case.path)
			if err != nil {
				t.Error(err)
			} else {
				if fmt.Sprint(resp) != fmt.Sprint(_case.expected) {
					t.Errorf("%s != %s", resp, _case.expected)
				}
			}
		})
	}
}

func init() {
	// Tokens and Approle info is read from env variables.
	// This sets them up for the tests.
	_ = os.Setenv("VAULT_TOKEN", "root-token")
	_ = os.Setenv("VAULT_ROLE_ID", "319418d1-7a8b-2da6-46c3-e0301f3ce02a")
	_ = os.Setenv("VAULT_SECRET_ID", "ce5e446d-3a60-54b6-5996-78b8f04ec03b")
}
