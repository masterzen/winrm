package winrm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

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
		/* credssp and kerberos is currently unimplemented, leave holder for future to keep in sync with python implementation
		case "credssp":
			encryption.protocolString = []byte("application/HTTP-CredSSP-session-encrypted")
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
	var userName, domain string
	if strings.Contains(client.username, "@") {
		parts := strings.Split(client.username, "@")
		domain = parts[1]
		userName = parts[0]
	} else if strings.Contains(client.username, "\\") {
		parts := strings.Split(client.username, "\\")
		domain = parts[0]
		userName = parts[1]
	} else {
		userName = client.username
	}

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
			message_chunks = append(message_chunks, message[i:i+sixTenKB])
		}
		for _, message_chunk := range message_chunks {
			encrypted_chunk := e.encryptMessage(message_chunk, host)
			encrypted_message = append(encrypted_message, encrypted_chunk...)
		}
	} else {
		content_type = "multipart/encrypted"
		encrypted_message = e.encryptMessage(message, host)
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

	resp, err := e.ntlmhttp.Do(req)
	if err != nil {
		return "", fmt.Errorf("unknown error %w", err)
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

func (e *Encryption) encryptMessage(message []byte, host string) []byte {
	encryptedStream, _ := e.buildMessage(message, host)

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

	return messagePayload
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
		decryptedMessage, err := e.decryptMessage(encryptedData, host)
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

func (e *Encryption) decryptMessage(encryptedData []byte, host string) ([]byte, error) {
	switch e.protocol {
	case "ntlm":
		return e.decryptNtlmMessage(encryptedData, host)
		/* credssp and kerberos is currently unimplemented, leave holder for future to keep in sync with python implementation
		case "credssp":
			return e.decryptCredsspMessage(encryptedData, host)
		case "kerberos":
			return e.decryptKerberosMessage(encryptedData, host)
		*/
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

/* credssp and kerberos is currently unimplemented, leave holder for future to keep in sync with python implementation
func (e *Encryption) decryptCredsspMessage(encryptedData []byte, host string) ([]byte, error) {
	// // TODO
	// encryptedMessage := encryptedData[4:]

	// credsspContext, ok := e.session.Auth.Contexts()[host]
	// if !ok {
	// 	return nil, fmt.Errorf("credssp context not found for host: %s", host)
	// }

	// message, err := credsspContext.Unwrap(encryptedMessage)
	// if err != nil {
	// 	return nil, err
	// }
	// return message, nil
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
}
*/

func (e *Encryption) buildMessage(encryptedData []byte, host string) ([]byte, error) {
	switch e.protocol {
	case "ntlm":
		return e.buildNTLMMessage(encryptedData, host)
		/* credssp and kerberos is currently unimplemented, leave holder for future to keep in sync with python implementation
		case "credssp":
			return e.buildCredSSPMessage(encryptedData, host)
		case "kerberos":
			return e.buildKerberosMessage(encryptedData, host)
		*/
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

/* credssp and kerberos is currently unimplemented, leave holder for future to keep in sync with python implementation
func (e *Encryption) buildCredSSPMessage(message []byte, host string) ([]byte, error) {
	// //TODO
	// context := e.session.Auth.Contexts[host]
	// sealedMessage := context.Wrap(message)

	// cipherNegotiated := context.TLSConnection.ConnectionState().CipherSuite.Name
	// trailerLength := e.getCredSSPTrailerLength(len(message), cipherNegotiated)

	// trailer := make([]byte, 4)
	// binary.LittleEndian.PutUint32(trailer, uint32(trailerLength))

	// return append(trailer, sealedMessage...), nil
}

func (e *Encryption) buildKerberosMessage(message []byte, host string) ([]byte, error) {
	// //TODO
	// sealedMessage, signature := e.session.Auth.WrapWinrm(host, message)

	// signatureLength := make([]byte, 4)
	// binary.LittleEndian.PutUint32(signatureLength, uint32(len(signature)))

	// return append(append(signatureLength, signature...), sealedMessage...), nil
}

func (e *Encryption) getCredSSPTrailerLength(messageLength int, cipherSuite string) int {
	var trailerLength int

	if match, _ := regexp.MatchString("^.*-GCM-[\\w\\d]*$", cipherSuite); match {
		trailerLength = 16
	} else {
		hashAlgorithm := cipherSuite[strings.LastIndex(cipherSuite, "-")+1:]
		var hashLength int

		if hashAlgorithm == "MD5" {
			hashLength = 16
		} else if hashAlgorithm == "SHA" {
			hashLength = 20
		} else if hashAlgorithm == "SHA256" {
			hashLength = 32
		} else if hashAlgorithm == "SHA384" {
			hashLength = 48
		} else {
			hashLength = 0
		}

		prePadLength := messageLength + hashLength
		paddingLength := 0

		if strings.Contains(cipherSuite, "RC4") {
			paddingLength = 0
		} else if strings.Contains(cipherSuite, "DES") || strings.Contains(cipherSuite, "3DES") {
			paddingLength = 8 - (prePadLength % 8)

		} else {
			// AES is a 128 bit block cipher
			paddingLength = 16 - (prePadLength % 16)
		}

		trailerLength = (prePadLength + paddingLength) - messageLength
	}
	return trailerLength
}
*/
