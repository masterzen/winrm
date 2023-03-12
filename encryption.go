package winrm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	ntlmssp "github.com/CalypsoSys/bobntlmssp"
	ntlmhttp "github.com/CalypsoSys/bobntlmssp/http"
	"github.com/masterzen/winrm/soap"
)

type Encryption struct {
	ntlm           *ClientNTLM
	SIXTEN_KB      int
	MIME_BOUNDARY  []byte
	protocol       string
	protocolString []byte
	httpClient     *http.Client
	ntlmClient     *ntlmssp.Client
	ntlmhttp       *ntlmhttp.Client
}

const (
	SixteenKB      = 16384
	MimeBoundary   = "--Encrypted Boundary"
	defaultCipher  = "RC4-HMAC-NTLM"
	BoundaryLength = len(MimeBoundary)
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

	uses the most excellent NTLM library from https://github.com/bodgit/ntlmssp
	the modified vesion only differs in not outputing raw http request and response
*/
func NewEncryption(protocol string) (*Encryption, error) {
	encryption := &Encryption{
		ntlm:          &ClientNTLM{},
		SIXTEN_KB:     SixteenKB,
		MIME_BOUNDARY: []byte(MimeBoundary),
		protocol:      protocol,
	}

	switch protocol {
	case "ntlm":
		encryption.protocolString = []byte("application/HTTP-SPNEGO-session-encrypted")
		return encryption, nil
	case "credssp":
		encryption.protocolString = []byte("application/HTTP-CredSSP-session-encrypted")
	case "kerberos":
		encryption.protocolString = []byte("application/HTTP-SPNEGO-session-encrypted")
	}

	return nil, fmt.Errorf("Encryption for protocol '%s' not supported in bobwinrm", protocol)
}

func (e *Encryption) Transport(endpoint *Endpoint) error {
	e.httpClient = &http.Client{}
	return e.ntlm.Transport(endpoint)
}

func (e *Encryption) Post(client *Client, message *soap.SoapMessage) (string, error) {
	e.ntlmClient, _ = ntlmssp.NewClient(ntlmssp.SetUserInfo(client.username, client.password), ntlmssp.SetVersion(ntlmssp.DefaultVersion()))
	e.ntlmhttp, _ = ntlmhttp.NewClient(e.httpClient, e.ntlmClient)
	e.ntlmhttp.Debug = false

	if e.PrepareRequest(client, client.url) == nil {
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

	req.Header.Set("User-Agent", "Bob WinRM client")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")

	resp, err := e.ntlmhttp.Do(req)
	if err != nil {
		return fmt.Errorf("unknown error %w", err)
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

	if e.protocol == "credssp" && len(message) > e.SIXTEN_KB {
		content_type = "multipart/x-multi-encrypted"
		encrypted_message = []byte{}
		message_chunks := [][]byte{}
		for i := 0; i < len(message); i += e.SIXTEN_KB {
			message_chunks = append(message_chunks, message[i:i+e.SIXTEN_KB])
		}
		for _, message_chunk := range message_chunks {
			encrypted_chunk := e.encryptMessage(message_chunk, host)
			encrypted_message = append(encrypted_message, encrypted_chunk...)
		}
	} else {
		content_type = "multipart/encrypted"
		encrypted_message = e.encryptMessage(message, host)
	}

	encrypted_message = append(encrypted_message, e.MIME_BOUNDARY...)
	encrypted_message = append(encrypted_message, []byte("--\r\n")...)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(encrypted_message))
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Bob WinRM client")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(encrypted_message)))
	req.Header.Set("Content-Type", content_type+";protocol=\""+string(e.protocolString)+"\";boundary=\"Encrypted Boundary\"")

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
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (e *Encryption) encryptMessage(message []byte, host string) []byte {
	messageLength := []byte(fmt.Sprintf("%d", len(message)))
	encryptedStream, _ := e.buildMessage(message, host)

	messagePayload := bytes.Join([][]byte{
		e.MIME_BOUNDARY,
		[]byte("\r\n"),
		[]byte("\tContent-Type: " + string(e.protocolString) + "\r\n"),
		[]byte("\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + string(messageLength) + "\r\n"),
		e.MIME_BOUNDARY,
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

func (e *Encryption) decryptResponse(response *http.Response, host string) ([]byte, error) {
	body, _ := ioutil.ReadAll(response.Body)
	parts := deleteEmpty(bytes.Split(body, []byte(MimeBoundary+"\r\n")))
	var message []byte

	for i := 0; i < len(parts); i += 2 {
		header := parts[i]
		payload := parts[i+1]

		expectedLengthStr := bytes.SplitAfter(header, []byte("Length="))[1]
		expectedLength, _ := strconv.Atoi(string(bytes.TrimSpace(expectedLengthStr)))

		// remove the end MIME block if it exists
		if bytes.HasSuffix(payload, []byte(MimeBoundary+"--\r\n")) {
			payload = payload[:len(payload)-BoundaryLength-4]
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
	case "credssp":
		return e.decryptCredsspMessage(encryptedData, host)
	case "kerberos":
		return e.decryptKerberosMessage(encryptedData, host)
	default:
		return nil, errors.New("Encryption for protocol " + e.protocol + " not supported in pywinrm")
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

func (e *Encryption) decryptCredsspMessage(encryptedData []byte, host string) ([]byte, error) {
	/*
		TODO
		encryptedMessage := encryptedData[4:]

		credsspContext, ok := e.session.Auth.Contexts()[host]
		if !ok {
			return nil, fmt.Errorf("credssp context not found for host: %s", host)
		}

		message, err := credsspContext.Unwrap(encryptedMessage)
		if err != nil {
			return nil, err
		}
		return message, nil
	*/
	return nil, nil
}

func (enc *Encryption) decryptKerberosMessage(encryptedData []byte, host string) ([]byte, error) {
	/*
		TODO
		signatureLength := binary.LittleEndian.Uint32(encryptedData[0:4])
		signature := encryptedData[4 : 4+signatureLength]
		encryptedMessage := encryptedData[4+signatureLength:]

		message, err := enc.session.Auth.UnwrapWinrm(host, encryptedMessage, signature)
		if err != nil {
			return nil, err
		}

		return message, nil
	*/
	return nil, nil
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
		return nil, errors.New("Encryption for protocol " + e.protocol + " not supported in pywinrm")
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
	/*
		TODO
		context := e.session.Auth.Contexts[host]
		sealedMessage := context.Wrap(message)

		cipherNegotiated := context.TLSConnection.ConnectionState().CipherSuite.Name
		trailerLength := e.getCredSSPTrailerLength(len(message), cipherNegotiated)

		trailer := make([]byte, 4)
		binary.LittleEndian.PutUint32(trailer, uint32(trailerLength))

		return append(trailer, sealedMessage...), nil
	*/
	return nil, nil
}

func (e *Encryption) buildKerberosMessage(message []byte, host string) ([]byte, error) {
	/*
		sealedMessage, signature := e.session.Auth.WrapWinrm(host, message)

		signatureLength := make([]byte, 4)
		binary.LittleEndian.PutUint32(signatureLength, uint32(len(signature)))

		return append(append(signatureLength, signature...), sealedMessage...), nil
	*/
	return nil, nil
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
