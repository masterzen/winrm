package winrm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bodgit/ntlmssp"
	"github.com/masterzen/winrm/soap"
)

const (
	credSSPHeaderName = "CredSSP"

	// ntlmSignatureLength is the fixed size of an NTLM message signature
	// (version + checksum + sequence number). MS-CSSP carries this raw
	// signature immediately followed by the sealed data.
	ntlmSignatureLength = 16

	// defaultCredSSPTimeout bounds blocking waits when the caller supplied a
	// zero (unbounded) endpoint timeout.
	defaultCredSSPTimeout = 60 * time.Second

	// credSSPHandshakeDrainSettle is the idle window used to coalesce a full TLS
	// handshake flight (which crypto/tls may emit as several back-to-back
	// writes) into a single CredSSP token exchange, avoiding a partial flight
	// being POSTed on its own.
	credSSPHandshakeDrainSettle = 20 * time.Millisecond

	credSSPClientBindingLabel = "CredSSP Client-To-Server Binding Hash\x00"
	credSSPServerBindingLabel = "CredSSP Server-To-Client Binding Hash\x00"
)

// credSSPTimeout returns a usable timeout, applying a sane floor when the
// endpoint timeout is zero so that time.After does not fire immediately.
func credSSPTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultCredSSPTimeout
	}
	return d
}

var (
	errCredSSPClosed = errors.New("credssp connection is closed")

	// errCredSSPReauthRequired signals that the server rejected an encrypted
	// request as unauthenticated (HTTP 401), typically because the pinned
	// connection was dropped and re-dialed. It triggers a one-shot re-handshake.
	errCredSSPReauthRequired = errors.New("credssp re-authentication required")
)

type credSSPMemoryConn struct {
	readMu   sync.Mutex
	readBuf  bytes.Buffer
	incoming chan []byte
	outgoing chan []byte
	closeCh  chan struct{}

	deadlineMu   sync.Mutex
	readDeadline time.Time
}

func newCredSSPMemoryConn() *credSSPMemoryConn {
	return &credSSPMemoryConn{
		incoming: make(chan []byte, 32),
		outgoing: make(chan []byte, 32),
		closeCh:  make(chan struct{}),
	}
}

func (c *credSSPMemoryConn) Read(p []byte) (int, error) {
	for {
		c.readMu.Lock()
		if c.readBuf.Len() > 0 {
			n, _ := c.readBuf.Read(p)
			c.readMu.Unlock()
			return n, nil
		}
		c.readMu.Unlock()

		// Honor the read deadline so a truncated server flight cannot block
		// Read (and therefore readTSRequest / io.ReadFull) indefinitely.
		var timeout <-chan time.Time
		var timer *time.Timer
		c.deadlineMu.Lock()
		deadline := c.readDeadline
		c.deadlineMu.Unlock()
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			timeout = timer.C
		}

		select {
		case data, ok := <-c.incoming:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return 0, io.EOF
			}
			c.readMu.Lock()
			c.readBuf.Write(data)
			c.readMu.Unlock()
		case <-c.closeCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, io.EOF
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *credSSPMemoryConn) Write(p []byte) (int, error) {
	payload := append([]byte(nil), p...)
	select {
	case c.outgoing <- payload:
		return len(p), nil
	case <-c.closeCh:
		return 0, errCredSSPClosed
	}
}

func (c *credSSPMemoryConn) Close() error {
	select {
	case <-c.closeCh:
	default:
		close(c.closeCh)
	}
	return nil
}

func (c *credSSPMemoryConn) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (c *credSSPMemoryConn) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (c *credSSPMemoryConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *credSSPMemoryConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *credSSPMemoryConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (c *credSSPMemoryConn) pushIncoming(payload []byte) error {
	data := append([]byte(nil), payload...)
	select {
	case c.incoming <- data:
		return nil
	case <-c.closeCh:
		return errCredSSPClosed
	}
}

func (c *credSSPMemoryConn) popOutgoing(timeout time.Duration) ([]byte, error) {
	select {
	case payload := <-c.outgoing:
		return payload, nil
	case <-time.After(timeout):
		return nil, errors.New("timed out waiting for outgoing TLS records")
	case <-c.closeCh:
		return nil, io.EOF
	}
}

func (c *credSSPMemoryConn) drainOutgoing(first []byte) []byte {
	payload := append([]byte(nil), first...)
	for {
		select {
		case extra := <-c.outgoing:
			payload = append(payload, extra...)
		default:
			return payload
		}
	}
}

// drainOutgoingWithin coalesces the first chunk with any further chunks that
// arrive within the settle window. Unlike drainOutgoing (which returns as soon
// as the channel is momentarily empty), this waits a short idle period so a
// multi-write TLS flight produced by a concurrent handshake goroutine is not
// split across separate CredSSP token exchanges.
func (c *credSSPMemoryConn) drainOutgoingWithin(first []byte, settle time.Duration) []byte {
	payload := append([]byte(nil), first...)
	timer := time.NewTimer(settle)
	defer timer.Stop()
	for {
		select {
		case extra := <-c.outgoing:
			payload = append(payload, extra...)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(settle)
		case <-timer.C:
			return payload
		case <-c.closeCh:
			return payload
		}
	}
}

type dummyAddr string

func (d dummyAddr) Network() string {
	return "credssp"
}

func (d dummyAddr) String() string {
	return string(d)
}

// ClientCredSSP provides a transport via CredSSP.
type ClientCredSSP struct {
	clientRequest

	// MinimumVersion, when set, requires the server to negotiate at least this
	// CredSSP version. CredSSP versions 2-4 use the pre-CVE-2018-0886 public-key
	// binding, so a server claiming an old version silently downgrades the
	// binding scheme. Set MinimumVersion to 5 to refuse that downgrade. Zero
	// means only the protocol floor (version 2) is enforced.
	MinimumVersion int

	httpClient *http.Client
	endpoint   *Endpoint
	memConn    *credSSPMemoryConn
	tlsConn    *tls.Conn
	encryption *Encryption

	handshakeComplete bool
	// mu serializes all Post calls. CredSSP authentication state and the TLS
	// tunnel are bound to a single connection and are not safe for concurrent
	// use, so requests must run one at a time. A consequence is that a
	// long-polling Receive holds the lock until it returns, so concurrent
	// stdin sends are stalled behind it; real-time interactive stdin is
	// therefore not supported over CredSSP.
	mu sync.Mutex
}

// NewClientCredSSPWithDial creates a CredSSP client with custom dialer.
func NewClientCredSSPWithDial(dial func(network, addr string) (net.Conn, error)) *ClientCredSSP {
	return &ClientCredSSP{
		clientRequest: clientRequest{
			dial: dial,
		},
	}
}

// NewClientCredSSPWithProxyFunc creates a CredSSP client with custom proxy.
func NewClientCredSSPWithProxyFunc(proxyfunc func(req *http.Request) (*url.URL, error)) *ClientCredSSP {
	return &ClientCredSSP{
		clientRequest: clientRequest{
			proxyfunc: proxyfunc,
		},
	}
}

// NewClientCredSSP creates a CredSSP client.
func NewClientCredSSP() *ClientCredSSP {
	return &ClientCredSSP{}
}

// Transport creates the wrapped CredSSP transport.
func (c *ClientCredSSP) Transport(endpoint *Endpoint) error {
	if err := c.clientRequest.Transport(endpoint); err != nil {
		return err
	}
	c.endpoint = endpoint

	// Server-side CredSSP auth state lives on the specific TCP connection that
	// completed the handshake, so every subsequent encrypted request must reuse
	// that same connection. Pin the transport to a single, long-lived keep-alive
	// connection so http.Transport cannot silently open a fresh (unauthenticated)
	// socket for a later request.
	if transport, ok := c.clientRequest.transport.(*http.Transport); ok {
		transport.DisableKeepAlives = false
		transport.MaxConnsPerHost = 1
		transport.MaxIdleConns = 1
		transport.MaxIdleConnsPerHost = 1
		transport.IdleConnTimeout = 0
	}

	c.httpClient = &http.Client{Transport: c.clientRequest.transport}
	return nil
}

// Post makes post to the winrm soap service over CredSSP.
func (c *ClientCredSSP) Post(client *Client, request *soap.SoapMessage) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	body, err := c.post(client, request)
	if err != nil && errors.Is(err, errCredSSPReauthRequired) {
		// The server likely closed the idle keep-alive connection, so the
		// transport dialed a fresh, unauthenticated socket and rejected the
		// request. Reset CredSSP state and re-run the handshake once. A 401 is
		// safe to retry because the server never processed the request.
		c.resetHandshakeState()
		body, err = c.post(client, request)
	}
	return body, err
}

func (c *ClientCredSSP) post(client *Client, request *soap.SoapMessage) (string, error) {
	if err := c.ensureHandshake(client); err != nil {
		return "", err
	}

	if c.encryption == nil {
		encryption, err := NewEncryption("credssp")
		if err != nil {
			return "", err
		}
		encryption.httpClient = c.httpClient
		encryption.tlsConn = c.tlsConn
		encryption.credsspConn = c.memConn
		encryption.timeout = credSSPTimeout(c.endpoint.Timeout)
		c.encryption = encryption
	}

	return c.encryption.PrepareEncryptedRequest(client, client.url, []byte(request.String()))
}

func (c *ClientCredSSP) resetHandshakeState() {
	if c.memConn != nil {
		_ = c.memConn.Close()
	}
	c.handshakeComplete = false
	c.memConn = nil
	c.tlsConn = nil
	c.encryption = nil
}

func (c *ClientCredSSP) ensureHandshake(client *Client) error {
	if c.handshakeComplete {
		return nil
	}

	cfg, err := c.tlsConfig()
	if err != nil {
		return err
	}

	memConn := newCredSSPMemoryConn()
	tlsConn := tls.Client(memConn, cfg)

	handshakeErr := make(chan error, 1)
	go func() {
		handshakeErr <- tlsConn.Handshake()
	}()

	for {
		select {
		case err := <-handshakeErr:
			if err != nil {
				_ = memConn.Close()
				return fmt.Errorf("credssp tls handshake failed: %w", err)
			}

			c.memConn = memConn
			c.tlsConn = tlsConn
			if err := c.performCredSSPAuth(client); err != nil {
				_ = memConn.Close()
				return err
			}
			c.handshakeComplete = true
			return nil
		case out := <-memConn.outgoing:
			// Coalesce the whole TLS flight (crypto/tls may emit several writes
			// per flight from the handshake goroutine) into a single CredSSP
			// token exchange, waiting a short settle window so a partial flight
			// is never POSTed on its own.
			token, err := c.exchangeCredSSPToken(client.url, memConn.drainOutgoingWithin(out, credSSPHandshakeDrainSettle), true)
			if err != nil {
				_ = memConn.Close()
				return fmt.Errorf("credssp tls handshake token exchange: %w", err)
			}
			if len(token) > 0 {
				if err := memConn.pushIncoming(token); err != nil {
					return err
				}
			}
		}
	}
}

func (c *ClientCredSSP) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		//nolint:gosec
		InsecureSkipVerify: c.endpoint.Insecure,
		ServerName:         c.endpoint.TLSServerName,
		// Pin TLS 1.2: the header-pump assumes strict request/response
		// lockstep, and TLS 1.3 completes the client handshake without a
		// final round-trip, which can leave the client Finished record
		// queued when Handshake() returns and desync app data.
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}

	if len(c.endpoint.CACert) > 0 {
		certPool, err := readCACerts(c.endpoint.CACert)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = certPool
	} else if !c.endpoint.Insecure {
		// Without a CA there is nothing to verify against; self-signed certs are
		// normal for CredSSP, so skip verification.
		cfg.InsecureSkipVerify = true
	}

	// crypto/tls requires a ServerName (or InsecureSkipVerify) to verify a
	// certificate; default it to the endpoint host so a CA-only config works.
	if !cfg.InsecureSkipVerify && cfg.ServerName == "" {
		cfg.ServerName = c.endpoint.Host
	}

	return cfg, nil
}

func (c *ClientCredSSP) performCredSSPAuth(client *Client) error {
	user, domain := splitUsername(client.username)
	ntlmClient, err := ntlmssp.NewClient(
		ntlmssp.SetUserInfo(user, client.password),
		ntlmssp.SetDomain(domain),
		ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
	)
	if err != nil {
		return err
	}

	negoToken, err := ntlmClient.Authenticate(nil, nil)
	if err != nil {
		return err
	}
	challengeRequest := tsRequest{
		Version:    credSSPDefaultVersion,
		NegoTokens: []negoDataItem{{NegoToken: negoToken}},
	}

	challengeResponse, err := c.sendTSRequest(client.url, challengeRequest)
	if err != nil {
		return fmt.Errorf("credssp negotiate/challenge exchange: %w", err)
	}
	if err := credSSPResponseError(challengeResponse); err != nil {
		return err
	}
	if challengeResponse == nil || len(challengeResponse.NegoTokens) == 0 {
		return errors.New("credssp challenge response missing NTLM challenge")
	}

	version, err := negotiateCredSSPVersion(credSSPDefaultVersion, challengeResponse.Version, c.MinimumVersion)
	if err != nil {
		return err
	}

	authToken, err := ntlmClient.Authenticate(challengeResponse.NegoTokens[0].NegoToken, nil)
	if err != nil {
		return err
	}

	securitySession := ntlmClient.SecuritySession()
	if securitySession == nil {
		return errors.New("credssp ntlm security session not established")
	}

	if len(c.tlsConn.ConnectionState().PeerCertificates) == 0 {
		return errors.New("credssp tls peer certificate missing")
	}
	serverPublicKey, err := credSSPCertificatePublicKey(c.tlsConn.ConnectionState().PeerCertificates[0])
	if err != nil {
		return err
	}

	nonce := []byte(nil)
	if version >= credSSPVersion5 {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
	}

	clientPubKeyAuth, expectedServerPubKeyAuth, err := buildPubKeyAuthData(securitySession, serverPublicKey, version, nonce)
	if err != nil {
		return err
	}

	// Send the final NTLM AUTHENTICATE token together with pubKeyAuth in a
	// single TSRequest, as in the canonical MS-CSSP exchange. The server
	// replies with its own pubKeyAuth for verification.
	pubKeyResponse, err := c.sendTSRequest(client.url, tsRequest{
		Version:     version,
		NegoTokens:  []negoDataItem{{NegoToken: authToken}},
		PubKeyAuth:  clientPubKeyAuth,
		ClientNonce: nonce,
	})
	if err != nil {
		return fmt.Errorf("credssp authenticate/pubKeyAuth exchange: %w", err)
	}
	if err := credSSPResponseError(pubKeyResponse); err != nil {
		return err
	}
	if pubKeyResponse == nil || len(pubKeyResponse.PubKeyAuth) == 0 {
		return errors.New("credssp pubKeyAuth response missing")
	}

	serverPubKeyAuth, err := unwrapCredSSPData(securitySession, pubKeyResponse.PubKeyAuth)
	if err != nil {
		return err
	}
	if !bytes.Equal(serverPubKeyAuth, expectedServerPubKeyAuth) {
		return errors.New("credssp pubKeyAuth verification failed")
	}

	credentials, err := marshalCredentials(domain, user, client.password)
	if err != nil {
		return err
	}
	wrappedCredentials, err := wrapCredSSPData(securitySession, credentials)
	if err != nil {
		return err
	}

	// authInfo is the last client message; a compliant server sends no
	// further TSRequest, so this exchange must be send-only. ClientNonce
	// belongs only with pubKeyAuth, so it is omitted here.
	if err := c.sendTSRequestNoReply(client.url, tsRequest{
		Version:  version,
		AuthInfo: wrappedCredentials,
	}); err != nil {
		return fmt.Errorf("credssp authInfo exchange: %w", err)
	}

	return nil
}

// negotiateCredSSPVersion clamps the client's version to what the server
// reports, rejecting servers below the protocol floor and below any caller-
// required minimum. requiredMinimum of 0 means only the protocol floor applies.
func negotiateCredSSPVersion(clientVersion, serverVersion, requiredMinimum int) (int, error) {
	if serverVersion < credSSPMinimumVersion {
		return 0, fmt.Errorf("credssp server reported unsupported version %d", serverVersion)
	}

	negotiated := clientVersion
	if serverVersion < negotiated {
		negotiated = serverVersion
	}

	minimum := requiredMinimum
	if minimum < credSSPMinimumVersion {
		minimum = credSSPMinimumVersion
	}
	if negotiated < minimum {
		return 0, fmt.Errorf("credssp negotiated version %d is below required minimum %d", negotiated, minimum)
	}

	return negotiated, nil
}

// credSSPResponseError returns an error if a server TSRequest carries a
// non-zero NTSTATUS error code, so authentication failures (bad credentials,
// policy denial, etc.) surface directly instead of as a vague downstream error.
func credSSPResponseError(response *tsRequest) error {
	if response != nil && response.ErrorCode != 0 {
		return fmt.Errorf("credssp server returned error code 0x%08X", uint32(response.ErrorCode))
	}
	return nil
}

// credSSPCertificatePublicKey returns the certificate's public key in the exact
// form CredSSP binds against: the PKCS#1 RSAPublicKey DER (SEQUENCE of modulus
// and exponent), NOT the full SubjectPublicKeyInfo. Windows and the reference
// implementations hash this PKCS#1 encoding, so using SubjectPublicKeyInfo makes
// pubKeyAuth verification fail on the server.
func credSSPCertificatePublicKey(cert *x509.Certificate) ([]byte, error) {
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("credssp requires an RSA server certificate, got %T", cert.PublicKey)
	}
	return x509.MarshalPKCS1PublicKey(rsaPub), nil
}

// computePubKeyAuthPlaintext returns the plaintext the client must wrap for
// pubKeyAuth and the plaintext it expects the server to return, per the
// negotiated CredSSP version.
//
// For v2-v4 the client sends the server's public key unmodified and the server
// returns it with its first byte incremented. For v5+ each side sends a SHA-256
// binding hash over a directional label, the client nonce, and the public key.
func computePubKeyAuthPlaintext(version int, nonce, serverPublicKey []byte) (clientPlaintext, expectedServer []byte) {
	if version >= credSSPVersion5 {
		clientPlaintext = credSSPBindingHash(credSSPClientBindingLabel, nonce, serverPublicKey)
		expectedServer = credSSPBindingHash(credSSPServerBindingLabel, nonce, serverPublicKey)
		return clientPlaintext, expectedServer
	}

	clientPlaintext = append([]byte(nil), serverPublicKey...)
	expectedServer = append([]byte(nil), serverPublicKey...)
	expectedServer[0]++
	return clientPlaintext, expectedServer
}

func buildPubKeyAuthData(session *ntlmssp.SecuritySession, serverPublicKey []byte, version int, nonce []byte) ([]byte, []byte, error) {
	clientPlaintext, expectedServer := computePubKeyAuthPlaintext(version, nonce, serverPublicKey)
	wrapped, err := wrapCredSSPData(session, clientPlaintext)
	if err != nil {
		return nil, nil, err
	}
	return wrapped, expectedServer, nil
}

func credSSPBindingHash(prefix string, nonce, publicKey []byte) []byte {
	hash := sha256.Sum256(bytes.Join([][]byte{
		[]byte(prefix),
		nonce,
		publicKey,
	}, nil))
	return hash[:]
}

// credSSPSecurityContext is the subset of *ntlmssp.SecuritySession used to seal
// and unseal CredSSP payloads. It exists so the wire framing can be tested with
// a fake peer without a full NTLM handshake.
type credSSPSecurityContext interface {
	Wrap(b []byte) ([]byte, []byte, error)
	Unwrap(b, signature []byte) ([]byte, error)
}

// wrapCredSSPData produces the raw SSPI output MS-CSSP expects in the
// pubKeyAuth and authInfo fields: the NTLM message signature (a fixed 16 bytes)
// immediately followed by the sealed data, with no length prefix.
func wrapCredSSPData(session credSSPSecurityContext, payload []byte) ([]byte, error) {
	sealed, signature, err := session.Wrap(payload)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, len(signature)+len(sealed))
	data = append(data, signature...)
	data = append(data, sealed...)
	return data, nil
}

func unwrapCredSSPData(session credSSPSecurityContext, payload []byte) ([]byte, error) {
	if len(payload) < ntlmSignatureLength {
		return nil, errors.New("invalid credssp payload")
	}

	signature := payload[:ntlmSignatureLength]
	sealed := payload[ntlmSignatureLength:]
	return session.Unwrap(sealed, signature)
}

// writeTSRequest marshals the request, pushes it through the TLS tunnel and
// returns the resulting TLS records (a full drained flight) to POST.
func (c *ClientCredSSP) writeTSRequest(request tsRequest) ([]byte, error) {
	payload, err := marshalTSRequest(request)
	if err != nil {
		return nil, err
	}

	if _, err := c.tlsConn.Write(payload); err != nil {
		return nil, err
	}

	outgoing, err := c.memConn.popOutgoing(credSSPTimeout(c.endpoint.Timeout))
	if err != nil {
		return nil, err
	}
	return c.memConn.drainOutgoing(outgoing), nil
}

// sendTSRequest sends a TSRequest and reads the server's TSRequest reply.
func (c *ClientCredSSP) sendTSRequest(endpoint string, request tsRequest) (*tsRequest, error) {
	tlsRecords, err := c.writeTSRequest(request)
	if err != nil {
		return nil, err
	}

	responseToken, err := c.exchangeCredSSPToken(endpoint, tlsRecords, true)
	if err != nil {
		return nil, err
	}
	if len(responseToken) > 0 {
		if err := c.memConn.pushIncoming(responseToken); err != nil {
			return nil, err
		}
	}

	return readTSRequest(c.tlsConn, credSSPTimeout(c.endpoint.Timeout))
}

// sendTSRequestNoReply sends a final TSRequest (e.g. authInfo) for which the
// server returns no further TSRequest, so it never blocks on a reply.
func (c *ClientCredSSP) sendTSRequestNoReply(endpoint string, request tsRequest) error {
	tlsRecords, err := c.writeTSRequest(request)
	if err != nil {
		return err
	}

	_, err = c.exchangeCredSSPToken(endpoint, tlsRecords, false)
	return err
}

func readTSRequest(conn net.Conn, timeout time.Duration) (*tsRequest, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer conn.SetReadDeadline(time.Time{})

	buffer := make([]byte, 0, 8192)
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			buffer = append(buffer, chunk[:n]...)
			// Use the outer DER SEQUENCE header to decide when a whole TSRequest
			// has arrived, rather than matching stdlib error strings.
			complete, total, derErr := derSequenceComplete(buffer)
			if derErr != nil {
				return nil, derErr
			}
			if complete {
				return unmarshalTSRequest(buffer[:total])
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			return nil, err
		}
	}
}

// derSequenceComplete reports whether buf contains a complete DER SEQUENCE by
// parsing its length header, returning the total length (header + content) of
// that SEQUENCE. It returns (false, 0, nil) when more bytes are still needed.
func derSequenceComplete(buf []byte) (bool, int, error) {
	if len(buf) < 2 {
		return false, 0, nil
	}
	if buf[0] != 0x30 {
		return false, 0, fmt.Errorf("unexpected ASN.1 tag 0x%02X, want SEQUENCE", buf[0])
	}

	first := buf[1]
	if first < 0x80 {
		total := 2 + int(first)
		return len(buf) >= total, total, nil
	}

	numBytes := int(first & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return false, 0, fmt.Errorf("invalid ASN.1 length encoding")
	}
	if len(buf) < 2+numBytes {
		return false, 0, nil
	}

	contentLen := 0
	for i := 0; i < numBytes; i++ {
		contentLen = (contentLen << 8) | int(buf[2+i])
	}
	total := 2 + numBytes + contentLen
	return len(buf) >= total, total, nil
}

func (c *ClientCredSSP) exchangeCredSSPToken(endpoint string, token []byte, requireToken bool) ([]byte, error) {
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "WinRM client")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", credSSPHeaderName, base64.StdEncoding.EncodeToString(token)))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return nil, err
	}

	responseToken, found, err := findCredSSPToken(resp.Header)
	if err != nil {
		return nil, err
	}

	if !found {
		// Surface a real HTTP failure (e.g. 500) rather than masking it as a
		// missing-token error. A token can legitimately accompany a 401 during
		// negotiation, so only treat a tokenless error status as a failure.
		if resp.StatusCode >= http.StatusBadRequest {
			return nil, fmt.Errorf("credssp exchange failed: HTTP %d", resp.StatusCode)
		}
		if requireToken {
			return nil, fmt.Errorf("credssp server did not return %s token", credSSPHeaderName)
		}
		return nil, nil
	}
	return responseToken, nil
}

func findCredSSPToken(headers http.Header) ([]byte, bool, error) {
	for _, value := range headers.Values("WWW-Authenticate") {
		if value == credSSPHeaderName {
			return nil, true, nil
		}
		prefix := credSSPHeaderName + " "
		if strings.HasPrefix(value, prefix) {
			payload := strings.TrimSpace(strings.TrimPrefix(value, prefix))
			token, err := base64.StdEncoding.DecodeString(payload)
			return token, true, err
		}
	}
	return nil, false, nil
}
