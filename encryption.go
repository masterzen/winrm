package winrm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm/soap"
)

// sixTenKB is the CredSSP chunk size (MS-CSSP): messages larger than this are
// split into multiple encrypted MIME parts, each independently sealed.
const sixTenKB = 16384

// errNTLMReauthRequired signals that the server rejected an encrypted NTLM
// request as unauthenticated (HTTP 401), typically because the connection
// that carried the NTLM authentication state was dropped and re-dialed. It
// triggers a one-shot re-handshake, mirroring errCredSSPReauthRequired
// (credssp.go).
var errNTLMReauthRequired = errors.New("NTLM re-authentication required")

// Encryption is a WinRM message-encryption transport selected by protocol
// (MS-WSMV §2.2.9.1). NTLM negotiates an azureNTLMSecuritySession (MS-NLMP
// §3.4, ntlm_security_session.go) directly over HTTP and wraps/unwraps
// message bodies through the shared messageProtector-based MIME framing in
// message_encryption.go. Kerberos delegates entirely to ClientKerberos,
// which owns the Kerberos security context. CredSSP's ongoing message
// encryption is genuine TLS application data (not an NTLM-style
// Wrap/Unwrap), driven directly through tlsConn/credsspConn -- NTLM-style
// sealing is only used for CredSSP's pubKeyAuth handshake step, a separate
// code path in credssp.go.
type Encryption struct {
	ntlm              *ClientNTLM
	kerberos          *ClientKerberos
	raw               clientRequest
	protocol          string
	protocolString    []byte
	httpClient        *http.Client
	messageEncryption *winRMMessageEncryption

	// mu serializes Post's NTLM negotiate/request/retry sequence. Different
	// goroutines can call Post concurrently on the same Encryption; without
	// this lock they can race on messageEncryption's sequence numbers and on
	// winRMMessageEncryption.multipart.
	mu sync.Mutex

	// ntlmKeyExchangeOptions controls the minimum NTLM key strength accepted
	// when establishing an azureNTLMSecuritySession. The zero value accepts
	// whatever the server negotiates, matching bodgit/ntlmssp's historical
	// default.
	ntlmKeyExchangeOptions NTLMKeyExchangeOptions

	// tlsConn/credsspConn/timeout are used only when protocol == "credssp".
	// They are populated by ClientCredSSP (credssp.go) after its handshake
	// establishes the TLS tunnel; Encryption itself never dials or
	// negotiates CredSSP.
	tlsConn     *tls.Conn
	credsspConn *credSSPMemoryConn
	timeout     time.Duration
}

// NewEncryption creates a WinRM message-encryption transport for protocol.
// Supported protocols are "ntlm" and "kerberos". For Kerberos, use
// NewEncryptionWithSettings when possible so the authentication configuration
// is installed before the transport is initialized.
func NewEncryption(protocol string) (*Encryption, error) {
	return NewEncryptionWithSettings(protocol, nil)
}

// NewEncryptionWithSettings creates a protocol-selected WinRM message-
// encryption transport and applies the supplied authentication settings.
func NewEncryptionWithSettings(protocol string, settings *Settings) (*Encryption, error) {
	switch protocol {
	case "ntlm":
		var ntlmKeyExchangeOptions NTLMKeyExchangeOptions
		if settings != nil {
			ntlmKeyExchangeOptions = settings.NTLMKeyExchangeOptions
		}
		return &Encryption{
			ntlm:                   &ClientNTLM{},
			protocol:               protocol,
			protocolString:         []byte("application/HTTP-SPNEGO-session-encrypted"),
			ntlmKeyExchangeOptions: ntlmKeyExchangeOptions,
		}, nil
	case "kerberos":
		kerberos := &ClientKerberos{}
		if settings != nil {
			kerberos = NewClientKerberos(settings)
		}
		return &Encryption{
			kerberos:       kerberos,
			protocol:       protocol,
			protocolString: []byte("application/HTTP-SPNEGO-session-encrypted"),
		}, nil
	case "credssp":
		// ClientCredSSP (credssp.go) drives the handshake itself and populates
		// tlsConn/credsspConn/httpClient/timeout directly after constructing
		// this value; PrepareEncryptedRequest is called directly, bypassing
		// Post/Transport below.
		return &Encryption{
			protocol:       protocol,
			protocolString: []byte("application/HTTP-CredSSP-session-encrypted"),
		}, nil
	default:
		return nil, fmt.Errorf("encryption for protocol %q not supported", protocol)
	}
}

func (e *Encryption) Transport(endpoint *Endpoint) error {
	if e.protocol == "kerberos" {
		if e.kerberos == nil {
			return fmt.Errorf("kerberos encryption transport is not configured")
		}
		return e.kerberos.Transport(endpoint)
	}
	if err := e.ntlm.Transport(endpoint); err != nil {
		return err
	}
	// e.ntlm's Negotiator-wrapped transport is retained only for the
	// fallback, unencrypted request path (used when message-encryption
	// negotiation itself fails, see Post below). e.raw is a second, plain
	// *http.Transport dialed the same way; e.httpClient (built from it)
	// drives the Azure-based NTLM negotiate/challenge/authenticate handshake
	// and the already-sealed encrypted requests directly, via manual
	// Authorization header handling rather than a RoundTripper middleware.
	e.raw.dial = e.ntlm.dial
	e.raw.proxyfunc = e.ntlm.proxyfunc
	if err := e.raw.Transport(endpoint); err != nil {
		return err
	}
	e.httpClient = &http.Client{Transport: e.raw.transport}
	return nil
}

func (e *Encryption) Post(client *Client, message *soap.SoapMessage) (string, error) {
	if e.protocol == "kerberos" {
		if e.kerberos == nil {
			return "", fmt.Errorf("kerberos encryption transport is not configured")
		}
		return e.kerberos.Post(client, message)
	}
	if e.httpClient == nil {
		return "", fmt.Errorf("NTLM encryption transport is not initialized")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.PrepareRequest(client, client.url); err != nil {
		// Preserve the existing behavior: if message encryption negotiation is
		// unavailable, make the request through the regular NTLM transport.
		return e.ntlm.Post(client, message)
	}

	body, err := e.PrepareEncryptedRequest(client, client.url, []byte(message.String()))
	if err != nil && errors.Is(err, errNTLMReauthRequired) {
		// The connection that held the NTLM authentication state was lost --
		// for example the server closed an idle keep-alive connection and the
		// transport dialed a fresh, unauthenticated socket. Re-run the NTLM
		// handshake and retry once. A 401 is safe to retry because the server
		// never processed the encrypted request.
		if err := e.PrepareRequest(client, client.url); err != nil {
			return "", err
		}
		body, err = e.PrepareEncryptedRequest(client, client.url, []byte(message.String()))
	}
	return body, err
}

// PrepareRequest negotiates NTLM message encryption: it runs the NTLM
// negotiate/challenge/authenticate exchange over endpoint (each leg sent as
// an Authorization: Negotiate header, MS-NLMP §3.3.1), derives an
// azureNTLMSecuritySession from the resulting exported session key
// (MS-NLMP §3.4), and installs it as e.messageEncryption's protector.
func (e *Encryption) PrepareRequest(client *Client, endpoint string) error {
	if e.httpClient == nil {
		return fmt.Errorf("NTLM HTTP client is not initialized")
	}

	negotiateChallenge := func(negotiateToken []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(context.Background(), "POST", endpoint, nil)
		if err != nil {
			return nil, err
		}
		setWinRMHeaders(req, "application/soap+xml;charset=UTF-8", 0)
		req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negotiateToken))

		resp, err := e.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("negotiate NTLM message encryption: %w", err)
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return nil, fmt.Errorf("read NTLM challenge response: %w", err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			return nil, fmt.Errorf("NTLM negotiation expected an HTTP 401 challenge, got %d", resp.StatusCode)
		}
		challengeToken, err := negotiateResponseToken(resp.Header.Values("WWW-Authenticate"))
		if err != nil {
			return nil, fmt.Errorf("read NTLM challenge: %w", err)
		}
		return challengeToken, nil
	}

	authenticateToken, sessionKey, negotiateFlags, err := negotiateAzureNTLMSessionKey(client.username, client.password, negotiateChallenge)
	if err != nil {
		return fmt.Errorf("negotiate NTLM message encryption: %w", err)
	}

	authReq, err := http.NewRequestWithContext(context.Background(), "POST", endpoint, nil)
	if err != nil {
		return err
	}
	setWinRMHeaders(authReq, "application/soap+xml;charset=UTF-8", 0)
	authReq.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authenticateToken))

	resp, err := e.httpClient.Do(authReq)
	if err != nil {
		return fmt.Errorf("complete NTLM message encryption negotiation: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("read NTLM negotiation response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NTLM negotiation returned HTTP %d", resp.StatusCode)
	}

	azureSession, err := newAzureNTLMSecuritySession(sessionKey, negotiateFlags, true, e.ntlmKeyExchangeOptions)
	if err != nil {
		return fmt.Errorf("establish NTLM security session: %w", err)
	}
	e.messageEncryption, err = newWinRMMessageEncryption("ntlm", azureNTLMMessageProtector{session: azureSession})
	if err != nil {
		return err
	}
	return nil
}

func (e *Encryption) PrepareEncryptedRequest(_ *Client, endpoint string, message []byte) (string, error) {
	// CredSSP's ongoing message encryption is plain TLS application data
	// written directly through tlsConn/credsspConn, not the NTLM-style
	// messageProtector path below. See the Encryption struct's doc comment.
	if e.protocol == "credssp" {
		return e.prepareCredSSPEncryptedRequest(endpoint, message)
	}

	if e.messageEncryption == nil {
		return "", fmt.Errorf("NTLM message encryption is not initialized")
	}
	encryptedMessage, err := e.messageEncryption.encrypt(message)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(context.Background(), "POST", endpoint, bytes.NewReader(encryptedMessage))
	if err != nil {
		return "", err
	}
	setWinRMHeaders(req, e.messageEncryption.contentType(), len(encryptedMessage))

	// The NTLM authentication state (established by PrepareRequest above)
	// lives on the underlying TCP connection, not in any per-request header,
	// so this and subsequent encrypted requests are sent unauthenticated on
	// e.httpClient and rely on connection reuse to stay on that connection.
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send encrypted NTLM request: %w", err)
	}

	// A 401 here means the NTLM authentication state tied to this connection
	// was lost, not that the encrypted message was rejected. Report it as a
	// reauthentication condition instead of falling through to
	// ParseEncryptedResponse, which would otherwise return the 401 error page
	// as if it were the decrypted SOAP response.
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return "", errNTLMReauthRequired
	}

	body, err := e.ParseEncryptedResponse(resp)
	return string(body), err
}

// prepareCredSSPEncryptedRequest builds and sends a CredSSP-encrypted WinRM
// request. Ported from PR #188's original Encryption.PrepareEncryptedRequest,
// scoped to the "credssp" protocol only (the "ntlm" case above uses the
// Azure-based azureNTLMMessageProtector through the same messageProtector
// path; CredSSP will join it in a subsequent commit).
func (e *Encryption) prepareCredSSPEncryptedRequest(endpoint string, message []byte) (string, error) {
	if e.httpClient == nil {
		return "", fmt.Errorf("CredSSP encryption transport is not initialized")
	}

	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	host := strings.Split(parsedURL.Hostname(), ":")[0]

	var contentType string
	var encryptedMessage []byte

	if len(message) > sixTenKB {
		contentType = "multipart/x-multi-encrypted"
		var messageChunks [][]byte
		for i := 0; i < len(message); i += sixTenKB {
			end := i + sixTenKB
			if end > len(message) {
				end = len(message)
			}
			messageChunks = append(messageChunks, message[i:end])
		}
		for _, messageChunk := range messageChunks {
			encryptedChunk, err := e.encryptMessage(messageChunk, host)
			if err != nil {
				return "", err
			}
			encryptedMessage = append(encryptedMessage, encryptedChunk...)
		}
	} else {
		contentType = "multipart/encrypted"
		encryptedMessage, err = e.encryptMessage(message, host)
		if err != nil {
			return "", err
		}
	}

	encryptedMessage = append(encryptedMessage, []byte(mimeBoundary)...)
	encryptedMessage = append(encryptedMessage, []byte("--\r\n")...)

	req, err := http.NewRequestWithContext(context.Background(), "POST", endpoint, bytes.NewReader(encryptedMessage))
	if err != nil {
		return "", err
	}
	setWinRMHeaders(req, fmt.Sprintf(`%s;protocol="%s";boundary="Encrypted Boundary"`, contentType, e.protocolString), len(encryptedMessage))

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send encrypted CredSSP request: %w", err)
	}

	// A 401 on an encrypted CredSSP request means the connection is no longer
	// authenticated (typically re-dialed after the server dropped the pinned
	// socket). Signal the transport to re-run the handshake.
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return "", errCredSSPReauthRequired
	}

	body, err := e.ParseEncryptedResponse(resp)
	return string(body), err
}

func setWinRMHeaders(req *http.Request, contentType string, contentLength int) {
	req.Header.Set("User-Agent", "WinRM client")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = int64(contentLength)
}

func (e *Encryption) ParseEncryptedResponse(response *http.Response) ([]byte, error) {
	if response == nil {
		return nil, fmt.Errorf("NTLM response is nil")
	}
	if e.protocol == "credssp" {
		if strings.Contains(response.Header.Get("Content-Type"), fmt.Sprintf(`protocol="%s"`, e.protocolString)) {
			return e.decryptCredSSPResponse(response)
		}
	} else if e.messageEncryption != nil && strings.Contains(response.Header.Get("Content-Type"), fmt.Sprintf(`protocol="%s"`, e.messageEncryption.protocolString)) {
		return e.messageEncryption.decryptResponse(response)
	}
	if response.Body == nil {
		return nil, fmt.Errorf("NTLM response body is nil")
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

// The functions below implement CredSSP's post-handshake message encryption.
// Ported from PR #188's original encryption.go as directly as reasonably
// possible: #188's flat Encryption struct grew a case "credssp" branch and a
// handful of protocol-specific helper methods alongside its NTLM ones, and
// this merge keeps that same shape rather than routing CredSSP through
// the shared messageProtector interface NTLM/Kerberos use (that unification
// is a later, separate refactor). CredSSP's message encryption is TLS, not
// NTLM sealing:
// credSSPMemoryConn (credssp.go) is an in-memory net.Conn that lets
// crypto/tls.Client/Server run a real TLS session whose wire bytes are
// captured instead of sent over a socket, so buildCredSSPMessage/
// decryptCredsspMessage below produce and consume genuine TLS application
// data.

// encryptMessage wraps message for the wire, producing a single MIME part
// (boundary, headers, and the protocol-sealed payload from buildMessage).
// PrepareEncryptedRequest chunks larger CredSSP messages into multiple calls
// to this function before appending the closing MIME boundary.
func (e *Encryption) encryptMessage(message []byte, host string) ([]byte, error) {
	// For CredSSP, buildMessage performs a real TLS write that can fail or
	// time out, so the error must be surfaced rather than producing a
	// malformed body.
	encryptedStream, err := e.buildMessage(message, host)
	if err != nil {
		return nil, err
	}

	messagePayload := bytes.Join([][]byte{
		[]byte(mimeBoundary),
		[]byte("\r\n"),
		[]byte(fmt.Sprintf("\tContent-Type: %s\r\n", string(e.protocolString))),
		[]byte(fmt.Sprintf("\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n", len(message))),
		[]byte(mimeBoundary),
		[]byte("\r\n"),
		[]byte("\tContent-Type: application/octet-stream\r\n"),
		encryptedStream,
	}, []byte{})

	return messagePayload, nil
}

// buildMessage dispatches to the protocol-specific sealing implementation.
// Only "credssp" is handled here -- "ntlm"'s equivalent path lives in
// azureNTLMMessageProtector.Wrap (ntlm_security_session.go, via
// messageEncryption), and "kerberos" message encryption is handled entirely
// by ClientKerberos, never reaching this type.
func (e *Encryption) buildMessage(message []byte, host string) ([]byte, error) {
	switch e.protocol {
	case "credssp":
		return e.buildCredSSPMessage(message, host)
	default:
		return nil, fmt.Errorf("encryption for protocol %q not supported by this path", e.protocol)
	}
}

// buildCredSSPMessage seals message by writing it to the CredSSP TLS tunnel
// and reading back the sealed TLS record bytes captured by credsspConn. The
// result is prefixed with a 4-byte little-endian MS-CSSP trailer length.
func (e *Encryption) buildCredSSPMessage(message []byte, host string) ([]byte, error) {
	if e.tlsConn == nil || e.credsspConn == nil {
		return nil, errors.New("credssp tls context not initialized")
	}

	if _, err := e.tlsConn.Write(message); err != nil {
		return nil, err
	}
	sealedFirst, err := e.credsspConn.popOutgoing(credSSPTimeout(e.timeout))
	if err != nil {
		return nil, err
	}
	sealedMessage := e.credsspConn.drainOutgoing(sealedFirst)

	cipherSuite := tls.CipherSuiteName(e.tlsConn.ConnectionState().CipherSuite)
	trailerLength := e.getCredSSPTrailerLength(len(message), cipherSuite)

	trailer := make([]byte, 4)
	binary.LittleEndian.PutUint32(trailer, uint32(trailerLength)) //nolint:gosec // trailer length is bounded by a single TLS record's block/hash overhead.

	return append(trailer, sealedMessage...), nil
}

// getCredSSPTrailerLength computes the MS-CSSP trailer length (MAC/tag plus
// any block-cipher padding) for a message of messageLength bytes under the
// given TLS cipher suite name.
func (e *Encryption) getCredSSPTrailerLength(messageLength int, cipherSuite string) int {
	var trailerLength int

	if strings.Contains(cipherSuite, "_GCM_") || strings.Contains(cipherSuite, "-GCM-") {
		trailerLength = 16
	} else {
		hashAlgorithm := ""
		if strings.Contains(cipherSuite, "_") {
			hashAlgorithm = cipherSuite[strings.LastIndex(cipherSuite, "_")+1:]
		} else if strings.Contains(cipherSuite, "-") {
			hashAlgorithm = cipherSuite[strings.LastIndex(cipherSuite, "-")+1:]
		}

		var hashLength int
		switch hashAlgorithm {
		case "MD5":
			hashLength = 16
		case "SHA":
			hashLength = 20
		case "SHA256":
			hashLength = 32
		case "SHA384":
			hashLength = 48
		default:
			hashLength = 0
		}

		prePadLength := messageLength + hashLength
		paddingLength := 0

		if strings.Contains(cipherSuite, "RC4") || strings.Contains(cipherSuite, "CHACHA20") {
			paddingLength = 0
		} else if strings.Contains(cipherSuite, "3DES") || strings.Contains(cipherSuite, "DES") {
			paddingLength = 8 - (prePadLength % 8)
			if paddingLength == 8 {
				paddingLength = 0
			}
		} else {
			// AES is a 128 bit block cipher.
			paddingLength = 16 - (prePadLength % 16)
			if paddingLength == 16 {
				paddingLength = 0
			}
		}

		trailerLength = (prePadLength + paddingLength) - messageLength
	}
	return trailerLength
}

// decryptCredSSPResponse parses the CredSSP-encrypted MIME response body
// (one or more boundary-delimited parts, each with an OriginalContent
// Length= header) and decrypts each part in turn.
//
// Note: unlike message_encryption.go's generic decrypt() (used by NTLM/
// Kerberos), this keeps its own MIME parsing rather than going through
// winRMMessageEncryption/messageProtector, because decryptCredsspMessage
// needs the parsed expectedLength *before* reading from the TLS tunnel (a
// single TLS Read returns at most one record's plaintext, so the caller must
// know how many bytes to read across however many records the message
// spans). Unifying this with messageProtector is a later, separate refactor.
func (e *Encryption) decryptCredSSPResponse(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	parts := deleteEmpty(bytes.Split(body, []byte(fmt.Sprintf("%s\r\n", mimeBoundary))))
	var message []byte

	for i := 0; i < len(parts); i += 2 {
		header := parts[i]
		payload := parts[i+1]

		expectedLengthStr := bytes.SplitAfter(header, []byte("Length="))[1]
		expectedLength, err := strconv.Atoi(string(bytes.TrimSpace(expectedLengthStr)))
		if err != nil {
			return nil, err
		}

		// Remove the end MIME block if it exists.
		if bytes.HasSuffix(payload, []byte(fmt.Sprintf("%s--\r\n", mimeBoundary))) {
			payload = payload[:len(payload)-len(mimeBoundary)-4]
		}
		encryptedData := bytes.ReplaceAll(payload, []byte("\tContent-Type: application/octet-stream\r\n"), []byte{})
		decryptedMessage, err := e.decryptMessage(encryptedData, response.Request.URL.Hostname(), expectedLength)
		if err != nil {
			return nil, err
		}

		if len(decryptedMessage) != expectedLength {
			return nil, errors.New("encrypted length from server does not match the expected size, message has been tampered with")
		}

		message = append(message, decryptedMessage...)
	}

	return message, nil
}

// decryptMessage dispatches to the protocol-specific unsealing
// implementation. Only "credssp" is handled here, mirroring buildMessage
// above.
func (e *Encryption) decryptMessage(encryptedData []byte, host string, expectedLength int) ([]byte, error) {
	switch e.protocol {
	case "credssp":
		return e.decryptCredsspMessage(encryptedData, host, expectedLength)
	default:
		return nil, fmt.Errorf("encryption for protocol %q not supported by this path", e.protocol)
	}
}

// decryptCredsspMessage reverses buildCredSSPMessage: it strips the 4-byte
// trailer-length prefix, feeds the sealed TLS record bytes into the tunnel,
// and reads back expectedLength plaintext bytes from tlsConn. A message can
// span more than one TLS record, so io.ReadFull loops as needed.
func (e *Encryption) decryptCredsspMessage(encryptedData []byte, host string, expectedLength int) ([]byte, error) {
	if e.tlsConn == nil || e.credsspConn == nil {
		return nil, errors.New("credssp tls context not initialized")
	}
	if len(encryptedData) < 4 {
		return nil, errors.New("credssp encrypted payload too short")
	}

	// Skip the 4-byte CredSSP trailer length prefix and feed the wrapped TLS
	// record(s) into the tunnel.
	sealed := encryptedData[4:]
	if err := e.credsspConn.pushIncoming(sealed); err != nil {
		return nil, err
	}

	_ = e.tlsConn.SetReadDeadline(time.Now().Add(credSSPTimeout(e.timeout)))
	defer e.tlsConn.SetReadDeadline(time.Time{})

	// The plaintext length is authoritatively given by the MIME
	// OriginalContent header. A single Read returns at most one TLS record's
	// plaintext, so read the full declared length across however many
	// records it spans.
	message := make([]byte, expectedLength)
	if _, err := io.ReadFull(e.tlsConn, message); err != nil {
		return nil, err
	}

	return message, nil
}

// deleteEmpty drops zero-length byte slices, used when splitting CredSSP's
// MIME body on its boundary marker (which leaves an empty leading/trailing
// element).
func deleteEmpty(b [][]byte) [][]byte {
	var r [][]byte
	for _, by := range b {
		if len(by) != 0 {
			r = append(r, by)
		}
	}
	return r
}

// splitUsername splits a "user@domain" or "domain\user" credential into its
// user and domain parts. Used by credssp.go's performCredSSPAuth.
func splitUsername(input string) (string, string) {
	if strings.Contains(input, "@") {
		parts := strings.SplitN(input, "@", 2)
		return parts[0], parts[1]
	}
	if strings.Contains(input, "\\") {
		parts := strings.SplitN(input, "\\", 2)
		return parts[1], parts[0]
	}
	return input, ""
}
