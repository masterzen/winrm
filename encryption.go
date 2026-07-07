package winrm

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bodgit/ntlmssp"
	ntlmhttp "github.com/bodgit/ntlmssp/http"
	"github.com/masterzen/winrm/soap"
)

type Encryption struct {
	ntlm           *ClientNTLM
	protocol       string
	protocolString []byte
	httpClient     *http.Client
	ntlmClient     *ntlmssp.Client
	ntlmhttp       *ntlmhttp.Client
	tlsConn        *tls.Conn
	credsspConn    *credSSPMemoryConn
	timeout        time.Duration
}

const (
	sixTenKB       = 16384
	mimeBoundary   = "--Encrypted Boundary"
	defaultCipher  = "RC4-HMAC-NTLM"
	boundaryLength = len(mimeBoundary)
)

/*
Encrypted Message Types
When using Encryption, there are three options available

 1. Negotiate/SPNEGO

 2. Kerberos

 3. CredSSP

    protocol: The protocol string used for the particular auth protocol

    The auth protocol used, will determine the wrapping and unwrapping method plus
    the protocol string to use. Currently only NTLM is supported

    based on the python code from https://pypi.org/project/pywinrm/

    see https://github.com/diyan/pywinrm/blob/master/winrm/encryption.py

    uses the most excellent NTLM library from https://github.com/bodgit/ntlmssp
*/
func NewEncryption(protocol string) (*Encryption, error) {
	encryption := &Encryption{
		ntlm:     &ClientNTLM{},
		protocol: protocol,
	}

	switch protocol {
	case "ntlm":
		encryption.protocolString = []byte("application/HTTP-SPNEGO-session-encrypted")
		return encryption, nil
	case "credssp":
		encryption.protocolString = []byte("application/HTTP-CredSSP-session-encrypted")
		return encryption, nil
		/* kerberos is currently unimplemented, leave holder for future to keep in sync with python implementation
		case "kerberos": // kerberos is currently unimplemented, leave holder for future to keep in sync with python implementation
				encryption.protocolString = []byte("application/HTTP-SPNEGO-session-encrypted")
		*/
	}

	return nil, fmt.Errorf("Encryption for protocol '%s' not supported", protocol)
}

func (e *Encryption) Transport(endpoint *Endpoint) error {
	e.httpClient = &http.Client{}
	return e.ntlm.Transport(endpoint)
}

func (e *Encryption) Post(client *Client, message *soap.SoapMessage) (string, error) {
	// Note: CredSSP does not use this path. ClientCredSSP.Post drives the
	// handshake and calls PrepareEncryptedRequest directly.
	userName, domain := splitUsername(client.username)
	e.ntlmClient, _ = ntlmssp.NewClient(ntlmssp.SetUserInfo(userName, client.password), ntlmssp.SetDomain(domain), ntlmssp.SetVersion(ntlmssp.DefaultVersion()))
	e.ntlmhttp, _ = ntlmhttp.NewClient(e.httpClient, e.ntlmClient)

	var err error
	if err = e.PrepareRequest(client, client.url); err == nil {
		return e.PrepareEncryptedRequest(client, client.url, []byte(message.String()))
	} else {
		return e.ntlm.Post(client, message)
	}
}

func (e *Encryption) PrepareRequest(client *Client, endpoint string) error {
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "WinRM client")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")

	resp, err := e.ntlmhttp.Do(req)
	if err != nil {
		return fmt.Errorf("unknown error %w", err)
	}

	if _, err := io.ReadAll(resp.Body); err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("close request body: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("http error %d", resp.StatusCode)
	}

	return nil
}

/*
Creates a prepared request to send to the server with an encrypted message
and correct headers

:param endpoint: The endpoint/server to prepare requests to
:param message: The unencrypted message to send to the server
:return: A prepared request that has an decrypted message
*/
func (e *Encryption) PrepareEncryptedRequest(client *Client, endpoint string, message []byte) (string, error) {
	url, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	host := strings.Split(url.Hostname(), ":")[0]

	var content_type string
	var encrypted_message []byte

	if e.protocol == "credssp" && len(message) > sixTenKB {
		content_type = "multipart/x-multi-encrypted"
		encrypted_message = []byte{}
		message_chunks := [][]byte{}
		for i := 0; i < len(message); i += sixTenKB {
			end := i + sixTenKB
			if end > len(message) {
				end = len(message)
			}
			message_chunks = append(message_chunks, message[i:end])
		}
		for _, message_chunk := range message_chunks {
			encrypted_chunk, err := e.encryptMessage(message_chunk, host)
			if err != nil {
				return "", err
			}
			encrypted_message = append(encrypted_message, encrypted_chunk...)
		}
	} else {
		content_type = "multipart/encrypted"
		encrypted_message, err = e.encryptMessage(message, host)
		if err != nil {
			return "", err
		}
	}

	encrypted_message = append(encrypted_message, []byte(mimeBoundary)...)
	encrypted_message = append(encrypted_message, []byte("--\r\n")...)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(encrypted_message))
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "WinRM client")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(encrypted_message)))
	req.Header.Set("Content-Type", fmt.Sprintf(`%s;protocol="%s";boundary="Encrypted Boundary"`, content_type, e.protocolString))

	var resp *http.Response
	switch e.protocol {
	case "ntlm":
		resp, err = e.ntlmhttp.Do(req)
	case "credssp":
		resp, err = e.httpClient.Do(req)
	default:
		return "", errors.New("Encryption for protocol " + e.protocol + " not supported")
	}
	if err != nil {
		return "", fmt.Errorf("unknown error %w", err)
	}

	// A 401 on an encrypted CredSSP request means the connection is no longer
	// authenticated (typically re-dialed after the server dropped the pinned
	// socket). Signal the transport to re-run the handshake.
	if e.protocol == "credssp" && resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return "", errCredSSPReauthRequired
	}

	body, err := e.ParseEncryptedResponse(resp)

	return string(body), err
}

/*
Takes in the encrypted response from the server and decrypts it

:param response: The response that needs to be decrytped
:return: The unencrypted message from the server
*/
func (e *Encryption) ParseEncryptedResponse(response *http.Response) ([]byte, error) {
	contentType := response.Header.Get("Content-Type")
	if strings.Contains(contentType, fmt.Sprintf(`protocol="%s"`, e.protocolString)) {
		return e.decryptResponse(response, response.Request.URL.Hostname())
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (e *Encryption) encryptMessage(message []byte, host string) ([]byte, error) {
	// For CredSSP, buildMessage performs a real TLS write that can fail or time
	// out, so the error must be surfaced rather than producing a malformed body.
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

func deleteEmpty(b [][]byte) [][]byte {
	var r [][]byte
	for _, by := range b {
		if len(by) != 0 {
			r = append(r, by)
		}
	}
	return r
}

// tried using pkg.go.dev/mime/multipart here but parsing fails with with
// because in the header we have "\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n"
// on call to textproto.ReadMIMEHeader
// because of "The first line cannot start with a leading space."
func (e *Encryption) decryptResponse(response *http.Response, host string) ([]byte, error) {
	body, _ := io.ReadAll(response.Body)
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

		// remove the end MIME block if it exists
		if bytes.HasSuffix(payload, []byte(fmt.Sprintf("%s--\r\n", mimeBoundary))) {
			payload = payload[:len(payload)-boundaryLength-4]
		}
		encryptedData := bytes.ReplaceAll(payload, []byte("\tContent-Type: application/octet-stream\r\n"), []byte{})
		decryptedMessage, err := e.decryptMessage(encryptedData, host, expectedLength)
		if err != nil {
			return nil, err
		}

		actualLength := int(len(decryptedMessage))
		if actualLength != expectedLength {
			return nil, errors.New("encrypted length from server does not match the expected size, message has been tampered with")
		}

		message = append(message, decryptedMessage...)
	}

	return message, nil
}

func (e *Encryption) decryptMessage(encryptedData []byte, host string, expectedLength int) ([]byte, error) {
	switch e.protocol {
	case "ntlm":
		return e.decryptNtlmMessage(encryptedData, host)
	case "credssp":
		return e.decryptCredsspMessage(encryptedData, host, expectedLength)
	case "kerberos":
		return e.decryptKerberosMessage(encryptedData, host)
	default:
		return nil, errors.New("Encryption for protocol " + e.protocol + " not supported")
	}
}

func (e *Encryption) decryptNtlmMessage(encryptedData []byte, host string) ([]byte, error) {
	signatureLength := int(binary.LittleEndian.Uint32(encryptedData[:4]))
	signature := encryptedData[4 : signatureLength+4]
	encryptedMessage := encryptedData[signatureLength+4:]

	message, err := e.ntlmClient.SecuritySession().Unwrap(encryptedMessage, signature)
	if err != nil {
		return nil, err
	}
	return message, nil
}

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

	// The plaintext length is authoritatively given by the MIME OriginalContent
	// header. A single Read returns at most one TLS record's plaintext, so read
	// the full declared length across however many records it spans.
	message := make([]byte, expectedLength)
	if _, err := io.ReadFull(e.tlsConn, message); err != nil {
		return nil, err
	}

	return message, nil
}

func (enc *Encryption) decryptKerberosMessage(encryptedData []byte, host string) ([]byte, error) {
	// //TODO
	// signatureLength := binary.LittleEndian.Uint32(encryptedData[0:4])
	// signature := encryptedData[4 : 4+signatureLength]
	// encryptedMessage := encryptedData[4+signatureLength:]

	// message, err := enc.session.Auth.UnwrapWinrm(host, encryptedMessage, signature)
	// if err != nil {
	// 	return nil, err
	// }

	// return message, nil
	return nil, errors.New("kerberos encryption is not implemented")
}

func (e *Encryption) buildMessage(encryptedData []byte, host string) ([]byte, error) {
	switch e.protocol {
	case "ntlm":
		return e.buildNTLMMessage(encryptedData, host)
	case "credssp":
		return e.buildCredSSPMessage(encryptedData, host)
	case "kerberos":
		return e.buildKerberosMessage(encryptedData, host)
	default:
		return nil, errors.New("Encryption for protocol " + e.protocol + " not supported")
	}
}

func (enc *Encryption) buildNTLMMessage(message []byte, host string) ([]byte, error) {
	if enc.ntlmClient.SecuritySession() == nil {
		return nil, nil
	}
	sealedMessage, signature, err := enc.ntlmClient.SecuritySession().Wrap(message)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err = binary.Write(buf, binary.LittleEndian, uint32(len(signature))); err != nil {
		return nil, err
	}

	buf.Write(signature)
	buf.Write(sealedMessage)

	return buf.Bytes(), nil
}

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
	binary.LittleEndian.PutUint32(trailer, uint32(trailerLength))

	return append(trailer, sealedMessage...), nil
}

func (e *Encryption) buildKerberosMessage(message []byte, host string) ([]byte, error) {
	// //TODO
	// sealedMessage, signature := e.session.Auth.WrapWinrm(host, message)

	// signatureLength := make([]byte, 4)
	// binary.LittleEndian.PutUint32(signatureLength, uint32(len(signature)))

	// return append(append(signatureLength, signature...), sealedMessage...), nil
	return nil, errors.New("kerberos encryption is not implemented")
}

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
			// AES is a 128 bit block cipher
			paddingLength = 16 - (prePadLength % 16)
			if paddingLength == 16 {
				paddingLength = 0
			}
		}

		trailerLength = (prePadLength + paddingLength) - messageLength
	}
	return trailerLength
}

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
