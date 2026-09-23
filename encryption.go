package winrm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/masterzen/winrm/soap"
)

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
// which owns the Kerberos security context. CredSSP has its own dedicated
// transport, ClientCredSSP (credssp.go): its ongoing message encryption is
// genuine TLS application data (not an NTLM-style Wrap/Unwrap), driven
// through a credsspMessageProtector built from the TLS tunnel established by
// performCredSSPAuth -- it never goes through this type. NTLM-style sealing
// is used only for CredSSP's pubKeyAuth handshake step, a separate code path
// in credssp.go.
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
}

// NewEncryption creates a WinRM message-encryption transport for protocol.
// Supported protocols are "ntlm" and "kerberos". CredSSP has its own
// dedicated transport, ClientCredSSP (credssp.go), and is not constructed
// through this function. For Kerberos, use NewEncryptionWithSettings when
// possible so the authentication configuration is installed before the
// transport is initialized.
func NewEncryption(protocol string) (*Encryption, error) {
	if protocol == "kerberos" {
		return nil, fmt.Errorf("kerberos encryption requires realm, SPN, and credentials; use NewEncryptionWithSettings instead")
	}
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
	if e.messageEncryption != nil && strings.Contains(response.Header.Get("Content-Type"), fmt.Sprintf(`protocol="%s"`, e.messageEncryption.protocolString)) {
		return e.messageEncryption.decryptResponse(response)
	}
	if response.Body == nil {
		return nil, fmt.Errorf("NTLM response body is nil")
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
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
