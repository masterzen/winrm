package winrm

import (
	"bytes"
	"crypto/rc4"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	ntlmssp "github.com/Azure/go-ntlmssp"
	"github.com/masterzen/winrm/soap"
)

const sealedContentType = `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`

// ClientNTLM provides a transport via NTLMv2, negotiating message
// confidentiality (key exchange/sealing) whenever the server requires it.
type ClientNTLM struct {
	clientRequest
}

// Transport creates the wrapped NTLM transport
func (c *ClientNTLM) Transport(endpoint *Endpoint) error {
	if err := c.clientRequest.Transport(endpoint); err != nil {
		return err
	}

	// NTLM authentication, is scoped to a
	// single TCP connection, so the underlying transport must not spread the
	// handshake and subsequent sealed requests across different conns.
	if t, ok := c.clientRequest.transport.(*http.Transport); ok {
		t.MaxConnsPerHost = 1
		t.MaxIdleConnsPerHost = 1
	}

	c.clientRequest.transport = newNTLMSealingTransport(c.clientRequest.transport)
	return nil
}

// Post make post to the winrm soap service (forwarded to clientRequest implementation)
func (c ClientNTLM) Post(client *Client, request *soap.SoapMessage) (string, error) {
	return c.clientRequest.Post(client, request)
}

// NewClientNTLMWithDial NewClientNTLMWithDial
func NewClientNTLMWithDial(dial func(network, addr string) (net.Conn, error)) *ClientNTLM {
	return &ClientNTLM{
		clientRequest{
			dial: dial,
		},
	}
}

// NewClientNTLMWithProxyFunc NewClientNTLMWithProxyFunc
func NewClientNTLMWithProxyFunc(proxyfunc func(req *http.Request) (*url.URL, error)) *ClientNTLM {
	return &ClientNTLM{
		clientRequest{
			proxyfunc: proxyfunc,
		},
	}
}

// ntlmSealingTransport implements WinRM's NTLM message-level encryption
// (MS-WSMV §3.1.4.2). WinRM authentication is conn scoped, so the
// AUTHENTICATE message and the first sealed request body must be sent
// together in a single HTTP request. Subsequent requests reuse the
// negotiated session key and are sealed with the same key
type ntlmSealingTransport struct {
	inner http.RoundTripper

	mu               sync.Mutex
	authenticated    bool
	clientSealCipher *rc4.Cipher
	clientSignKey    []byte
	serverSealCipher *rc4.Cipher
	serverSignKey    []byte
	clientSeqNum     uint32
}

func newNTLMSealingTransport(inner http.RoundTripper) *ntlmSealingTransport {
	return &ntlmSealingTransport{inner: inner}
}

func (t *ntlmSealingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	t.mu.Lock()
	needsAuth := !t.authenticated
	t.mu.Unlock()

	if needsAuth {
		return t.authenticateAndSend(req, body)
	}

	resp, err := t.sendSealed(req, body)
	if err != nil {
		return nil, err
	}
	// A 401 here means the session is stale, so redo the full handshake.
	if resp.StatusCode == http.StatusUnauthorized {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		t.mu.Lock()
		t.authenticated = false
		t.clientSealCipher = nil
		t.serverSealCipher = nil
		t.clientSeqNum = 0
		t.mu.Unlock()
		return t.authenticateAndSend(req, body)
	}
	return resp, nil
}

// authenticateAndSend performs the full NTLM 3-leg handshake and sends the
// sealed payload together with the AUTHENTICATE message in the final leg.
//
//	Leg 1: anonymous POST -> 401 + WWW-Authenticate schema
//	Leg 2: POST + Authorization: <schema> <negotiate-token> -> 401 + challenge token
//	Leg 3: POST + Authorization: <schema> <authenticate-token> + sealed body -> response
func (t *ntlmSealingTransport) authenticateAndSend(req *http.Request, body []byte) (*http.Response, error) {
	username, password, ok := req.BasicAuth()
	if !ok {
		return nil, fmt.Errorf("ntlm: request has no credentials to negotiate with")
	}

	ctx := req.Context()

	// Leg 1: anonymous request to discover the auth schema.
	anonReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.inner.RoundTrip(anonReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		// No authentication required
		return resp, nil
	}
	schema, ok := ntlmSchema(resp.Header.Get("Www-Authenticate"))
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if !ok {
		return nil, fmt.Errorf("ntlm: server did not offer NTLM/Negotiate authentication")
	}

	// Leg 2: send NEGOTIATE requesting key exchange, receive challenge.
	negMsg, err := ntlmssp.NewNegotiateMessageWithOptions(ntlmssp.NegotiateMessageOptions{
		RequestSealing: true,
	})
	if err != nil {
		return nil, err
	}
	negReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), nil)
	if err != nil {
		return nil, err
	}
	negReq.Header.Set("Authorization", schema+" "+base64.StdEncoding.EncodeToString(negMsg))
	resp, err = t.inner.RoundTrip(negReq)
	if err != nil {
		return nil, err
	}
	challengeHeader := resp.Header.Get("Www-Authenticate")
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("ntlm: expected 401 with challenge, got %d", resp.StatusCode)
	}

	_, challengeB64, _ := strings.Cut(challengeHeader, " ")
	challenge, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil || len(challenge) == 0 {
		return nil, fmt.Errorf("ntlm: decode challenge: %w", err)
	}

	// Build the AUTHENTICATE message and obtain the exported session key.
	var sessionKey []byte
	authMsg, err := ntlmssp.NewAuthenticateMessage(challenge, username, password, &ntlmssp.AuthenticateMessageOptions{
		ExportedSessionKey: &sessionKey,
		RequireSealing:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("ntlm: build authenticate message: %w", err)
	}

	cs, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	if err != nil {
		return nil, err
	}
	ss, err := rc4.NewCipher(deriveServerSealKey(sessionKey))
	if err != nil {
		return nil, err
	}
	clientSignKey := deriveClientSignKey(sessionKey)
	serverSignKey := deriveServerSignKey(sessionKey)

	t.mu.Lock()
	t.clientSealCipher = cs
	t.clientSignKey = clientSignKey
	t.serverSealCipher = ss
	t.serverSignKey = serverSignKey
	seqNum := t.clientSeqNum
	t.clientSeqNum++
	t.authenticated = true
	t.mu.Unlock()

	// Leg 3: AUTHENTICATE + sealed body in one request
	ciphertext, sig := sealMessage(cs, clientSignKey, seqNum, body)
	multiBody := buildMultipartEncrypted(sig, ciphertext, len(body))

	authReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), bytes.NewReader(multiBody))
	if err != nil {
		return nil, err
	}
	copySealedHeaders(authReq, req)
	authReq.Header.Set("Authorization", schema+" "+base64.StdEncoding.EncodeToString(authMsg))
	authReq.Header.Set("Content-Type", sealedContentType)
	authReq.ContentLength = int64(len(multiBody))

	resp, err = t.inner.RoundTrip(authReq)
	if err != nil {
		return nil, err
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "multipart/encrypted") {
		return t.unsealResponse(resp)
	}
	return resp, nil
}

// sendSealed encrypts body and sends it on the already authenticated connection, without repeating the handshake.
func (t *ntlmSealingTransport) sendSealed(req *http.Request, body []byte) (*http.Response, error) {
	t.mu.Lock()
	seqNum := t.clientSeqNum
	t.clientSeqNum++
	cipher := t.clientSealCipher
	signKey := t.clientSignKey
	t.mu.Unlock()

	ciphertext, sig := sealMessage(cipher, signKey, seqNum, body)
	multiBody := buildMultipartEncrypted(sig, ciphertext, len(body))

	sealedReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), bytes.NewReader(multiBody))
	if err != nil {
		return nil, err
	}
	copySealedHeaders(sealedReq, req)
	sealedReq.Header.Set("Content-Type", sealedContentType)
	sealedReq.ContentLength = int64(len(multiBody))

	resp, err := t.inner.RoundTrip(sealedReq)
	if err != nil {
		return nil, err
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "multipart/encrypted") {
		return t.unsealResponse(resp)
	}
	return resp, nil
}

// unsealResponse decrypts a WinRM multipart/encrypted response body.
// rewrites the response so that callers see plain application/soap+xml.
func (t *ntlmSealingTransport) unsealResponse(resp *http.Response) (*http.Response, error) {
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	// After splitting on "--Encrypted Boundary" each part begins with "\r\n".
	// The octet-stream part is "\r\nContent-Type: application/octet-stream\r\n$payload".
	var payload []byte
	for _, part := range bytes.Split(raw, []byte("--Encrypted Boundary")) {
		data, ok := bytes.CutPrefix(part, []byte("\r\nContent-Type: application/octet-stream\r\n"))
		if !ok {
			continue
		}
		payload = data
		break
	}
	if len(payload) < 20 {
		return nil, fmt.Errorf("ntlm: encrypted response too short (%d bytes)", len(payload))
	}

	t.mu.Lock()
	serverCipher := t.serverSealCipher
	serverSignKey := t.serverSignKey
	t.mu.Unlock()

	plaintext, err := unsealMessage(serverCipher, serverSignKey, payload[4:20], payload[20:])
	if err != nil {
		return nil, fmt.Errorf("ntlm: unseal response: %w", err)
	}

	resp.Body = io.NopCloser(bytes.NewReader(plaintext))
	resp.ContentLength = int64(len(plaintext))
	resp.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	return resp, nil
}

// buildMultipartEncrypted constructs the WinRM multipart/encrypted body (MS-WSMV §3.1.4.2).
// no blank lines between header lines or between the last header and the binary payload.
func buildMultipartEncrypted(sig, ciphertext []byte, originalLen int) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf,
		"--Encrypted Boundary\r\n"+
			"Content-Type: application/HTTP-SPNEGO-session-encrypted\r\n"+
			"OriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n"+
			"--Encrypted Boundary\r\n"+
			"Content-Type: application/octet-stream\r\n",
		originalLen,
	)
	buf.Write([]byte{16, 0, 0, 0}) // 4-byte LE length of the signature
	buf.Write(sig)
	buf.Write(ciphertext)
	buf.WriteString("--Encrypted Boundary--\r\n")
	return buf.Bytes()
}

// copySealedHeaders copies headers from src to dst
// skip what the sealing transport recomputes itself.
func copySealedHeaders(dst, src *http.Request) {
	for k, v := range src.Header {
		if k == "Authorization" || k == "Content-Type" || k == "Content-Length" {
			continue
		}
		dst.Header[k] = v
	}
}

// ntlmSchema extracts "NTLM" or "Negotiate" from a Www-Authenticate header value.
func ntlmSchema(header string) (string, bool) {
	for _, schema := range []string{"NTLM", "Negotiate"} {
		if header == schema || strings.HasPrefix(header, schema+" ") {
			return schema, true
		}
	}
	return "", false
}
