package winrm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
)

func TestEndpointTLSConfigCurvePreferences(t *testing.T) {
	curves := []tls.CurveID{tls.X25519, tls.CurveP256}

	transports := map[string]func(t *testing.T) Transporter{
		"ClientNTLM": func(*testing.T) Transporter { return &ClientNTLM{} },
		"Encryption ntlm": func(t *testing.T) Transporter {
			enc, err := NewEncryption("ntlm")
			if err != nil {
				t.Fatal(err)
			}
			return enc
		},
	}

	for name, newTransport := range transports {
		t.Run(name, func(t *testing.T) {
			rec := newHelloRecorder(t)
			endpoint := rec.endpoint(t)
			endpoint.TLSConfig = &tls.Config{CurvePreferences: curves}

			params := *DefaultParameters
			params.TransportDecorator = func() Transporter { return newTransport(t) }
			client, err := NewClientWithParameters(endpoint, "test", "test", &params)
			if err != nil {
				t.Fatal(err)
			}
			// The NTLM handshake is expected to fail against this server;
			// only the ClientHello it sends matters here.
			_, _ = client.CreateShell()

			for _, hello := range rec.recordedHellos(t) {
				if !slices.Equal(hello.SupportedCurves, curves) {
					t.Errorf("SupportedCurves = %v, want %v", hello.SupportedCurves, curves)
				}
			}
		})
	}
}

func TestEndpointTLSConfigLayering(t *testing.T) {
	serverCertPool := func(rec *helloRecorder) *x509.CertPool {
		pool := x509.NewCertPool()
		pool.AddCert(rec.server.Certificate())
		return pool
	}

	tests := []struct {
		name string
		// setup configures the endpoint (Insecure is true by default).
		setup          func(rec *helloRecorder, endpoint *Endpoint)
		wantVerifyErr  bool
		wantServerName string
	}{
		{
			name: "CACert and TLSServerName override the base",
			setup: func(rec *helloRecorder, endpoint *Endpoint) {
				endpoint.Insecure = false
				// example.com is covered by the httptest certificate.
				endpoint.TLSServerName = "example.com"
				endpoint.CACert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rec.server.Certificate().Raw})
				endpoint.TLSConfig = &tls.Config{ServerName: "wrong.invalid", RootCAs: x509.NewCertPool()}
			},
			wantServerName: "example.com",
		},
		{
			name: "empty TLSServerName keeps the base ServerName",
			setup: func(rec *helloRecorder, endpoint *Endpoint) {
				endpoint.Insecure = false
				endpoint.TLSConfig = &tls.Config{ServerName: "example.com", RootCAs: serverCertPool(rec)}
			},
			wantServerName: "example.com",
		},
		{
			name: "Insecure true overrides base verification",
			setup: func(_ *helloRecorder, endpoint *Endpoint) {
				endpoint.TLSConfig = &tls.Config{InsecureSkipVerify: false}
			},
		},
		{
			name: "Insecure false overrides base InsecureSkipVerify",
			setup: func(_ *helloRecorder, endpoint *Endpoint) {
				endpoint.Insecure = false
				endpoint.TLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // must be overridden
			},
			wantVerifyErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newHelloRecorder(t)
			endpoint := rec.endpoint(t)
			tt.setup(rec, endpoint)
			base := endpoint.TLSConfig.Clone()

			client, err := NewClient(endpoint, "test", "test")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.CreateShell()
			switch {
			case tt.wantVerifyErr && !errors.As(err, new(*tls.CertificateVerificationError)):
				t.Fatalf("CreateShell error = %v, want a certificate verification error", err)
			case !tt.wantVerifyErr && err != nil:
				t.Fatalf("CreateShell: %v", err)
			}
			if tt.wantServerName != "" {
				for _, hello := range rec.recordedHellos(t) {
					if hello.ServerName != tt.wantServerName {
						t.Errorf("ServerName = %q, want %q", hello.ServerName, tt.wantServerName)
					}
				}
			}

			got := endpoint.TLSConfig
			if got.InsecureSkipVerify != base.InsecureSkipVerify || got.ServerName != base.ServerName || got.RootCAs != base.RootCAs {
				t.Errorf("TLSConfig was modified")
			}
		})
	}
}

func TestEndpointTLSConfigClientAuthRequest(t *testing.T) {
	curves := []tls.CurveID{tls.X25519, tls.CurveP256}
	otherCert, otherKey := newTestClientCert(t, "base")
	other, err := tls.X509KeyPair(otherCert, otherKey)
	if err != nil {
		t.Fatal(err)
	}

	rec := newHelloRecorder(t)
	endpoint := rec.endpoint(t)
	endpoint.Cert, endpoint.Key = newTestClientCert(t, "endpoint")
	endpoint.TLSConfig = &tls.Config{
		CurvePreferences: curves,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &other, nil
		},
	}

	if _, err := newClientAuthClient(t, endpoint).CreateShell(); err != nil {
		t.Fatalf("CreateShell: %v", err)
	}
	for _, hello := range rec.recordedHellos(t) {
		if !slices.Equal(hello.SupportedCurves, curves) {
			t.Errorf("SupportedCurves = %v, want %v", hello.SupportedCurves, curves)
		}
	}
	certs := rec.recordedClientCerts()
	if len(certs) == 0 {
		t.Fatal("server received no client certificate")
	}
	for _, cert := range certs {
		if cert.Subject.CommonName != "endpoint" {
			t.Errorf("client certificate CN = %q, want %q", cert.Subject.CommonName, "endpoint")
		}
	}
}
