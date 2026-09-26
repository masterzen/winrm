package winrm

import (
	"io"
	"net/http"
	"testing"

	"net"
	"time"
)

// ntlmTestServeEncryptedResponse decrypts r's body, to confirm it really
// was sealed, and replies with responseBody encrypted the same way. It
// does not assert on the request's content: unlike encryption_ntlm_test.go's
// ntlmTestServeEncrypted, the tests below drive real ClientNTLM/CreateShell
// traffic, which carries a fresh message ID on every request, so an exact
// content match does not apply here.
func ntlmTestServeEncryptedResponse(t *testing.T, session *azureNTLMSecuritySession, responseBody string, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read encrypted request body: %v", err)
	}
	serverEncryption, err := newWinRMMessageEncryption("ntlm", azureNTLMMessageProtector{session: session})
	if err != nil {
		t.Fatalf("build server message encryption: %v", err)
	}
	if _, err := serverEncryption.decrypt(body); err != nil {
		t.Fatalf("decrypt request body: %v", err)
	}
	encryptedResponse, err := serverEncryption.encrypt([]byte(responseBody))
	if err != nil {
		t.Fatalf("encrypt response body: %v", err)
	}
	w.Header().Set("Content-Type", serverEncryption.contentType())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encryptedResponse)
}

// ntlmTestChallengeFlags grants NTLM message sealing (MS-NLMP
// §2.2.2.5) with 128-bit extended session security and key exchange, the
// combination the handshake in ntlm_sealing_transport.go requires.
func ntlmTestChallengeFlags() uint32 {
	return uint32(ntlmTestNegotiateUnicode | ntlmTestNegotiateNTLM |
		ntlmNegotiateSign | ntlmNegotiateSeal |
		ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate128 | ntlmNegotiateKeyExch)
}

func TestHttpNTLMRequest(t *testing.T) {
	var serverSession *azureNTLMSecuritySession
	ts := ntlmTestHandshakeServer(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, ntlmTestChallengeFlags(),
		func(session *azureNTLMSecuritySession) {
			serverSession = session
		},
		func(w http.ResponseWriter, r *http.Request) {
			if serverSession == nil {
				t.Fatalf("received an unauthenticated request before the NTLM handshake completed")
			}
			ntlmTestServeEncryptedResponse(t, serverSession, createShellResponse, w, r)
		},
	)
	defer ts.Close()

	host, port, err := FindHostAndPortFromURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := *DefaultParameters
	params.TransportDecorator = func() Transporter { return &ClientNTLM{} }
	client, err := NewClientWithParameters(endpoint, ntlmTestUsername, ntlmTestPassword, &params)
	if err != nil {
		t.Fatal(err)
	}

	shell, err := client.CreateShell()
	if err != nil {
		t.Fatal(err)
	}
	if shell.id != "67A74734-DD32-4F10-89DE-49A060483810" {
		t.Fatalf("shell id = %q, want %q", shell.id, "67A74734-DD32-4F10-89DE-49A060483810")
	}
}

func TestHttpNTLMViaCustomDialerRequest(t *testing.T) {
	normalDialer := (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial
	usedCustomDialer := false
	dial := func(network, addr string) (net.Conn, error) {
		usedCustomDialer = true
		return normalDialer(network, addr)
	}

	var serverSession *azureNTLMSecuritySession
	ts := ntlmTestHandshakeServer(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, ntlmTestChallengeFlags(),
		func(session *azureNTLMSecuritySession) {
			serverSession = session
		},
		func(w http.ResponseWriter, r *http.Request) {
			if serverSession == nil {
				t.Fatalf("received an unauthenticated request before the NTLM handshake completed")
			}
			ntlmTestServeEncryptedResponse(t, serverSession, createShellResponse, w, r)
		},
	)
	defer ts.Close()

	host, port, err := FindHostAndPortFromURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := *DefaultParameters
	params.TransportDecorator = func() Transporter { return NewClientNTLMWithDial(dial) }
	client, err := NewClientWithParameters(endpoint, ntlmTestUsername, ntlmTestPassword, &params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateShell(); err != nil {
		t.Fatal(err)
	}
	if !usedCustomDialer {
		t.Error("usedCustomDialer = false, want true")
	}
}

// TestNTLMSessionReusedAcrossRequests checks the case the sealing transport
// exists for: the NTLM handshake (negotiate leg, then authenticate leg)
// only happens once per connection, and a later request reuses the
// negotiated session -- no re-challenge, and (implied by
// ntlmTestHandshakeServer only invoking its encrypted-request callback when
// the request carries no Authorization header) no repeated Authorization
// header either.
func TestNTLMSessionReusedAcrossRequests(t *testing.T) {
	var serverSession *azureNTLMSecuritySession
	handshakes := 0
	encryptedRequests := 0

	ts := ntlmTestHandshakeServer(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, ntlmTestChallengeFlags(),
		func(session *azureNTLMSecuritySession) {
			handshakes++
			serverSession = session
		},
		func(w http.ResponseWriter, r *http.Request) {
			encryptedRequests++
			if serverSession == nil {
				t.Fatalf("received an unauthenticated request before the NTLM handshake completed")
			}
			ntlmTestServeEncryptedResponse(t, serverSession, createShellResponse, w, r)
		},
	)
	defer ts.Close()

	host, port, err := FindHostAndPortFromURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := *DefaultParameters
	params.TransportDecorator = func() Transporter { return &ClientNTLM{} }
	client, err := NewClientWithParameters(endpoint, ntlmTestUsername, ntlmTestPassword, &params)
	if err != nil {
		t.Fatal(err)
	}

	shell, err := client.CreateShell()
	if err != nil {
		t.Fatal(err)
	}
	if shell.id != "67A74734-DD32-4F10-89DE-49A060483810" {
		t.Fatalf("shell id = %q, want %q", shell.id, "67A74734-DD32-4F10-89DE-49A060483810")
	}
	if handshakes != 1 {
		t.Fatalf("completed NTLM handshakes after first CreateShell = %d, want 1", handshakes)
	}
	if encryptedRequests != 1 {
		t.Fatalf("encrypted requests after first CreateShell = %d, want 1", encryptedRequests)
	}

	shell, err = client.CreateShell()
	if err != nil {
		t.Fatal(err)
	}
	if shell.id != "67A74734-DD32-4F10-89DE-49A060483810" {
		t.Fatalf("shell id = %q, want %q", shell.id, "67A74734-DD32-4F10-89DE-49A060483810")
	}
	if handshakes != 1 {
		t.Fatalf("completed NTLM handshakes after second CreateShell = %d, want 1 (the session should be reused)", handshakes)
	}
	if encryptedRequests != 2 {
		t.Fatalf("encrypted requests after second CreateShell = %d, want 2", encryptedRequests)
	}
}

// TestNTLMTransportPinsSingleConnection checks that ClientNTLM.Transport
// pins the underlying *http.Transport to one connection per host. The NTLM
// negotiate/challenge/authenticate handshake runs as sequential RoundTrip
// calls on the shared transport, relying on connection reuse to keep every
// leg on the same socket; a second connection breaks the handshake.
func TestNTLMTransportPinsSingleConnection(t *testing.T) {
	client := &ClientNTLM{}
	endpoint := NewEndpoint("server.example.com", 5985, false, false, nil, nil, nil, 0)
	if err := client.Transport(endpoint); err != nil {
		t.Fatal(err)
	}

	sealing, ok := client.transport.(*ntlmSealingTransport)
	if !ok {
		t.Fatalf("ClientNTLM transport is %T, want *ntlmSealingTransport", client.transport)
	}

	transport, ok := sealing.inner.(*http.Transport)
	if !ok {
		t.Fatalf("sealing transport's underlying transport is %T, want *http.Transport", sealing.inner)
	}

	if transport.DisableKeepAlives {
		t.Error("DisableKeepAlives = true, want false")
	}
	if transport.MaxConnsPerHost != 1 {
		t.Errorf("MaxConnsPerHost = %d, want 1", transport.MaxConnsPerHost)
	}
	if transport.MaxIdleConnsPerHost != 1 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 1", transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout != 0 {
		t.Errorf("IdleConnTimeout = %v, want 0", transport.IdleConnTimeout)
	}
}
