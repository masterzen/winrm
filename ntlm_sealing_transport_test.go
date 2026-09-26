package winrm

import (
	"io"
	"net/http"
	"testing"

	"github.com/masterzen/winrm/soap"
)

// These tests drive ClientNTLM.Transport and ClientNTLM.Post directly,
// instead of Encryption (see encryption_ntlm_test.go), to check that a
// caller using ClientNTLM as a TransportDecorator -- without going through
// NewEncryption("ntlm") -- also gets sealed WinRM traffic. They reuse the
// fake NTLM server double from encryption_ntlm_test.go
// (ntlmTestHandshakeServer, ntlmTestServeEncrypted, and friends), which
// implements enough of MS-NLMP to drive a real negotiate/challenge/
// authenticate exchange plus MS-WSMV message-level encryption.

// TestNTLMSealingTransportHandshakeAndEncryptedPost drives ClientNTLM.Post
// end to end against an httptest.Server test double: a real NTLM
// negotiate/challenge/authenticate exchange, followed by a message-
// encrypted request/response. It checks that the request the server
// received was actually sealed (a non-plaintext Content-Type, decrypting to
// the expected SOAP body) and that the response comes back decrypted to
// the caller.
func TestNTLMSealingTransportHandshakeAndEncryptedPost(t *testing.T) {
	serverChallenge := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	challengeFlags := ntlmTestChallengeFlags()

	const responseBody = "<response>ok</response>"

	requestMsg := soap.NewMessage()
	requestMsg.NewBody()
	wantRequest := requestMsg.String()

	var serverSession *azureNTLMSecuritySession

	ts := ntlmTestHandshakeServer(t, serverChallenge, challengeFlags,
		func(session *azureNTLMSecuritySession) {
			serverSession = session
		},
		func(w http.ResponseWriter, r *http.Request) {
			if serverSession == nil {
				t.Errorf("received an unauthenticated request before the NTLM handshake completed")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			wantContentType := `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`
			if ct := r.Header.Get("Content-Type"); ct != wantContentType {
				t.Errorf("unexpected request Content-Type %q, want %q", ct, wantContentType)
			}
			ntlmTestServeEncrypted(t, serverSession, wantRequest, responseBody, w, r)
		},
	)
	defer ts.Close()

	ntlmClient := &ClientNTLM{}
	if err := ntlmClient.Transport(NewEndpoint("127.0.0.1", 0, false, false, nil, nil, nil, 0)); err != nil {
		t.Fatal(err)
	}

	client := &Client{username: ntlmTestUsername, password: ntlmTestPassword, url: ts.URL}

	body, err := ntlmClient.Post(client, requestMsg)
	if err != nil {
		t.Fatal(err)
	}
	if body != responseBody {
		t.Fatalf("response body = %q, want %q", body, responseBody)
	}
}

// TestNTLMSealingTransportReauthenticatesOn401 simulates a server that has
// lost the NTLM authentication state tied to the connection (for example a
// dropped TCP connection, or a server-side idle timeout) by answering the
// first encrypted request with a plain HTTP 401 instead of an encrypted
// response. ClientNTLM.Post must run a fresh NTLM handshake and retry the
// request transparently, succeeding on the second attempt.
func TestNTLMSealingTransportReauthenticatesOn401(t *testing.T) {
	serverChallenge := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challengeFlags := ntlmTestChallengeFlags()

	const responseBody = "<response>ok</response>"

	requestMsg := soap.NewMessage()
	requestMsg.NewBody()
	wantRequest := requestMsg.String()

	var serverSession *azureNTLMSecuritySession
	handshakes := 0
	encryptedAttempts := 0

	ts := ntlmTestHandshakeServer(t, serverChallenge, challengeFlags,
		func(session *azureNTLMSecuritySession) {
			handshakes++
			serverSession = session
		},
		func(w http.ResponseWriter, r *http.Request) {
			encryptedAttempts++
			if encryptedAttempts == 1 {
				// The connection's NTLM state is gone; the server rejects the
				// encrypted request outright instead of decrypting it.
				_, _ = io.Copy(io.Discard, r.Body)
				serverSession = nil
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if serverSession == nil {
				t.Errorf("received an unauthenticated request before the retried NTLM handshake completed")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			ntlmTestServeEncrypted(t, serverSession, wantRequest, responseBody, w, r)
		},
	)
	defer ts.Close()

	ntlmClient := &ClientNTLM{}
	if err := ntlmClient.Transport(NewEndpoint("127.0.0.1", 0, false, false, nil, nil, nil, 0)); err != nil {
		t.Fatal(err)
	}

	client := &Client{username: ntlmTestUsername, password: ntlmTestPassword, url: ts.URL}

	body, err := ntlmClient.Post(client, requestMsg)
	if err != nil {
		t.Fatal(err)
	}
	if body != responseBody {
		t.Fatalf("response body = %q, want %q", body, responseBody)
	}
	if encryptedAttempts != 2 {
		t.Fatalf("encrypted request attempts = %d, want 2 (one rejected with 401, one retried)", encryptedAttempts)
	}
	if handshakes != 2 {
		t.Fatalf("completed NTLM handshakes = %d, want 2 (initial plus the 401-triggered retry)", handshakes)
	}
}
