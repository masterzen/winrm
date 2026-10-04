package winrm

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// ntlmSealingTransport implements WinRM message-level encryption for NTLM
// (MS-WSMV section 3.1.4.2) as an http.RoundTripper. It uses the shared
// Azure/go-ntlmssp-backed NTLM security session (ntlm_security_session.go)
// and MIME framing (message_encryption.go) that Encryption's "ntlm"
// protocol also uses.
//
// A caller that builds a ClientNTLM directly, instead of going through
// NewEncryption("ntlm"), gets the same sealed traffic this way. Without
// it, WinRM requests sent through ClientNTLM carry NTLM authentication
// but no message confidentiality.
type ntlmSealingTransport struct {
	inner http.RoundTripper

	// mu serializes RoundTrip. Two goroutines can call Post on the same
	// ClientNTLM at the same time; without this lock they race on
	// messageEncryption and on the handshake state.
	mu                sync.Mutex
	messageEncryption *winRMMessageEncryption
}

func newNTLMSealingTransport(inner http.RoundTripper) *ntlmSealingTransport {
	return &ntlmSealingTransport{inner: inner}
}

// RoundTrip seals req's body and sends it. The first call on a new
// transport also runs the NTLM handshake. A 401 response to a sealed
// request means the connection's NTLM state was lost, so RoundTrip
// re-handshakes once and retries.
func (t *ntlmSealingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	username, password, ok := req.BasicAuth()
	if !ok {
		return nil, fmt.Errorf("ntlm: request has no credentials to negotiate with")
	}

	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.messageEncryption == nil {
		if err := t.handshake(req, username, password); err != nil {
			return nil, err
		}
	}

	resp, err := t.sendSealed(req, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// The session tied to this connection is stale. For example, the
		// server closed an idle connection and the transport dialed a
		// fresh, unauthenticated one. Redo the handshake once and retry.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		t.messageEncryption = nil
		if err := t.handshake(req, username, password); err != nil {
			return nil, err
		}
		return t.sendSealed(req, body)
	}
	return resp, nil
}

// handshake runs the NTLM negotiate/challenge/authenticate exchange over
// req's URL and installs the resulting security session. It mirrors
// Encryption.PrepareRequest (encryption.go), adapted to run inside an
// http.RoundTripper instead of against a *Client/*Endpoint.
func (t *ntlmSealingTransport) handshake(req *http.Request, username, password string) error {
	negotiateChallenge := func(negotiateToken []byte) ([]byte, error) { //nolint:contextcheck // negotiateAzureNTLMSessionKey's callback signature is fixed; it forwards req's context through the closure instead of taking a ctx parameter.
		negReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), nil)
		if err != nil {
			return nil, err
		}
		negReq.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negotiateToken))
		resp, err := t.inner.RoundTrip(negReq)
		if err != nil {
			return nil, fmt.Errorf("ntlm: negotiate message encryption: %w", err)
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return nil, fmt.Errorf("ntlm: read challenge response: %w", err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			return nil, fmt.Errorf("ntlm: negotiation expected an HTTP 401 challenge, got %d", resp.StatusCode)
		}
		challengeToken, err := negotiateResponseToken(resp.Header.Values("WWW-Authenticate"))
		if err != nil {
			return nil, fmt.Errorf("ntlm: read challenge: %w", err)
		}
		return challengeToken, nil
	}

	authenticateToken, sessionKey, negotiateFlags, err := negotiateAzureNTLMSessionKey(username, password, negotiateChallenge)
	if err != nil {
		return fmt.Errorf("ntlm: negotiate message encryption: %w", err)
	}

	authReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), nil)
	if err != nil {
		return err
	}
	authReq.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authenticateToken))
	resp, err := t.inner.RoundTrip(authReq)
	if err != nil {
		return fmt.Errorf("ntlm: complete message encryption negotiation: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("ntlm: read negotiation response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ntlm: negotiation returned HTTP %d", resp.StatusCode)
	}

	session, err := newAzureNTLMSecuritySession(sessionKey, negotiateFlags, true, NTLMKeyExchangeOptions{})
	if err != nil {
		return fmt.Errorf("ntlm: establish security session: %w", err)
	}
	t.messageEncryption, err = newWinRMMessageEncryption("ntlm", azureNTLMMessageProtector{session: session})
	return err
}

// sendSealed encrypts body and sends it on the already-authenticated
// connection. NTLM authentication state lives on the TCP connection, not
// in a per-request header, so a sealed request carries no Authorization
// header.
func (t *ntlmSealingTransport) sendSealed(req *http.Request, body []byte) (*http.Response, error) {
	encrypted, err := t.messageEncryption.encrypt(body)
	if err != nil {
		return nil, fmt.Errorf("ntlm: seal request body: %w", err)
	}

	sealedReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), bytes.NewReader(encrypted)) //nolint:gosec // req.URL is the caller-configured WinRM endpoint, the same URL the unsealed request already targeted; it is not attacker-controlled.
	if err != nil {
		return nil, err
	}
	for k, v := range req.Header {
		if k == "Authorization" || k == "Content-Type" || k == "Content-Length" {
			continue
		}
		sealedReq.Header[k] = v
	}
	sealedReq.Header.Set("Content-Type", t.messageEncryption.contentType())
	sealedReq.ContentLength = int64(len(encrypted))

	resp, err := t.inner.RoundTrip(sealedReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return resp, nil // caller (RoundTrip) decides whether to re-handshake
	}
	plaintext, err := t.messageEncryption.decryptResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("ntlm: unseal response: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(plaintext))
	resp.ContentLength = int64(len(plaintext))
	resp.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	return resp, nil
}
