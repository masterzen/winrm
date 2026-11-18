package winrm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// helloRecorder is a TLS test server that records the ClientHello of every
// handshake and the client certificate of every request, and answers each
// request with the CreateShell response fixture.
type helloRecorder struct {
	server      *httptest.Server
	mu          sync.Mutex
	hellos      []*tls.ClientHelloInfo
	clientCerts []*x509.Certificate
}

func newHelloRecorder(t *testing.T) *helloRecorder {
	t.Helper()
	r := &helloRecorder{}
	r.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.TLS.PeerCertificates) > 0 {
			r.mu.Lock()
			r.clientCerts = append(r.clientCerts, req.TLS.PeerCertificates[0])
			r.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/soap+xml")
		_, _ = w.Write([]byte(response))
	}))
	r.server.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.hellos = append(r.hellos, hello)
			return nil, nil
		},
	}
	r.server.StartTLS()
	t.Cleanup(r.server.Close)
	return r
}

// endpoint returns an HTTPS endpoint for the server with Insecure set.
func (r *helloRecorder) endpoint(t *testing.T) *Endpoint {
	t.Helper()
	host, port, err := FindHostAndPortFromURL(r.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return NewEndpoint(host, port, true, true, nil, nil, nil, 0)
}

func (r *helloRecorder) recordedHellos(t *testing.T) []*tls.ClientHelloInfo {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hellos) == 0 {
		t.Fatal("server received no ClientHello")
	}
	return slices.Clone(r.hellos)
}

func (r *helloRecorder) recordedClientCerts() []*x509.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.clientCerts)
}

// newTestClientCert returns a self-signed client certificate and its key in
// PEM.
func newTestClientCert(t *testing.T, commonName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func newClientAuthClient(t *testing.T, endpoint *Endpoint) *Client {
	t.Helper()
	params := *DefaultParameters
	params.TransportDecorator = func() Transporter { return &ClientAuthRequest{} }
	client, err := NewClientWithParameters(endpoint, "", "", &params)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestClientAuthRequestAppliesTLSServerName(t *testing.T) {
	rec := newHelloRecorder(t)
	endpoint := rec.endpoint(t)
	endpoint.TLSServerName = "example.com"
	endpoint.Cert, endpoint.Key = newTestClientCert(t, "endpoint")

	if _, err := newClientAuthClient(t, endpoint).CreateShell(); err != nil {
		t.Fatalf("CreateShell: %v", err)
	}
	for _, hello := range rec.recordedHellos(t) {
		if hello.ServerName != "example.com" {
			t.Errorf("ServerName = %q, want %q", hello.ServerName, "example.com")
		}
	}
}
