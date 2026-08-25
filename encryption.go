package winrm

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bodgit/ntlmssp"
	ntlmhttp "github.com/bodgit/ntlmssp/http"
	"github.com/masterzen/winrm/soap"
)

// Encryption is a WinRM message-encryption transport selected by protocol.
// NTLM uses the legacy transport in this type; Kerberos delegates to
// ClientKerberos, which owns the Kerberos security context.
type Encryption struct {
	ntlm              *ClientNTLM
	kerberos          *ClientKerberos
	raw               clientRequest
	protocol          string
	protocolString    []byte
	httpClient        *http.Client
	ntlmClient        *ntlmssp.Client
	ntlmhttp          *ntlmhttp.Client
	messageEncryption *winRMMessageEncryption
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
// CredSSP is intentionally not included until its authentication transport is
// available.
func NewEncryptionWithSettings(protocol string, settings *Settings) (*Encryption, error) {
	switch protocol {
	case "ntlm":
		return &Encryption{
			ntlm:           &ClientNTLM{},
			protocol:       protocol,
			protocolString: []byte("application/HTTP-SPNEGO-session-encrypted"),
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
	// The Azure NTLM negotiator above is retained for the fallback request
	// path. bodgit/ntlmssp performs its own handshake for encrypted messages
	// and requires the underlying transport to remain a *http.Transport.
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

	userName, domain := splitNTLMUser(client.username)
	var err error
	e.ntlmClient, err = ntlmssp.NewClient(
		ntlmssp.SetUserInfo(userName, client.password),
		ntlmssp.SetDomain(domain),
		ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
	)
	if err != nil {
		return "", fmt.Errorf("create NTLM client: %w", err)
	}
	e.ntlmhttp, err = ntlmhttp.NewClient(e.httpClient, e.ntlmClient)
	if err != nil {
		return "", fmt.Errorf("create NTLM HTTP client: %w", err)
	}

	if err := e.PrepareRequest(client, client.url); err != nil {
		// Preserve the existing behavior: if message encryption negotiation is
		// unavailable, make the request through the regular NTLM transport.
		return e.ntlm.Post(client, message)
	}

	e.messageEncryption, err = newWinRMMessageEncryption("ntlm", ntlmMessageProtector{client: e.ntlmClient})
	if err != nil {
		return "", err
	}
	return e.PrepareEncryptedRequest(client, client.url, []byte(message.String()))
}

func splitNTLMUser(user string) (name, domain string) {
	if before, after, found := strings.Cut(user, "@"); found {
		return before, after
	}
	if before, after, found := strings.Cut(user, "\\"); found {
		return after, before
	}
	return user, ""
}

func (e *Encryption) PrepareRequest(_ *Client, endpoint string) error {
	if e.ntlmhttp == nil {
		return fmt.Errorf("NTLM HTTP client is not initialized")
	}
	req, err := http.NewRequestWithContext(context.Background(), "POST", endpoint, nil)
	if err != nil {
		return err
	}
	setWinRMHeaders(req, "application/soap+xml;charset=UTF-8", 0)

	resp, err := e.ntlmhttp.Do(req)
	if err != nil {
		return fmt.Errorf("negotiate NTLM message encryption: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("read NTLM negotiation response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NTLM negotiation returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (e *Encryption) PrepareEncryptedRequest(_ *Client, endpoint string, message []byte) (string, error) {
	if e.messageEncryption == nil || e.ntlmhttp == nil {
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

	resp, err := e.ntlmhttp.Do(req)
	if err != nil {
		return "", fmt.Errorf("send encrypted NTLM request: %w", err)
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

type ntlmMessageProtector struct {
	client *ntlmssp.Client
}

func (p ntlmMessageProtector) Wrap(message []byte) ([]byte, error) {
	if p.client == nil || p.client.SecuritySession() == nil {
		return nil, fmt.Errorf("NTLM security session is not established")
	}
	sealed, signature, err := p.client.SecuritySession().Wrap(message)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, 4+len(signature)+len(sealed)))
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(signature))); err != nil { //nolint:gosec // WinRM length fields are 32-bit and the buffer is bounded by memory.
		return nil, err
	}
	buf.Write(signature)
	buf.Write(sealed)
	return buf.Bytes(), nil
}

func (p ntlmMessageProtector) Unwrap(encryptedData []byte) ([]byte, error) {
	if p.client == nil || p.client.SecuritySession() == nil {
		return nil, fmt.Errorf("NTLM security session is not established")
	}
	if len(encryptedData) < 4 {
		return nil, fmt.Errorf("NTLM encrypted payload is shorter than its length prefix")
	}
	signatureLength := int(binary.LittleEndian.Uint32(encryptedData[:4]))
	if signatureLength < 0 || signatureLength > len(encryptedData)-4 {
		return nil, fmt.Errorf("invalid NTLM signature length %d for payload of %d bytes", signatureLength, len(encryptedData))
	}
	signature := encryptedData[4 : 4+signatureLength]
	sealed := encryptedData[4+signatureLength:]
	return p.client.SecuritySession().Unwrap(sealed, signature)
}
