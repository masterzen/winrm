package winrm

import (
	"bytes"
	stdcontext "context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/masterzen/winrm/soap"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Settings holds all the information necessary to configure the provider.
type Settings struct {
	WinRMUsername          string
	WinRMPassword          string
	WinRMHost              string
	WinRMPort              int
	WinRMProto             string
	WinRMInsecure          bool
	WinRMMessageEncryption bool
	KrbRealm               string
	KrbConfig              string
	// KrbSpn is normally HTTP/<fully-qualified-hostname>. It must use the
	// hostname registered in Active Directory, not an IP address; Kerberos
	// service-ticket lookup is based on the SPN and IP literals generally do
	// not have a matching HTTP principal.
	KrbSpn               string
	KrbCCache            string
	WinRMUseNTLM         bool
	WinRMPassCredentials bool
}

type ClientKerberos struct {
	clientRequest
	Username          string
	Password          string
	Realm             string
	Hostname          string
	Port              int
	Proto             string
	SPN               string
	KrbConf           string
	KrbCCache         string
	MessageEncryption bool

	requestMu         sync.Mutex
	httpClient        *http.Client
	kerberosClient    *client.Client
	securityContext   *kerberosInitiatorContext
	messageEncryption *winRMMessageEncryption
}

func NewClientKerberos(settings *Settings) *ClientKerberos {
	return &ClientKerberos{
		Username:          settings.WinRMUsername,
		Password:          settings.WinRMPassword,
		Realm:             settings.KrbRealm,
		Hostname:          settings.WinRMHost,
		Port:              settings.WinRMPort,
		Proto:             settings.WinRMProto,
		KrbConf:           settings.KrbConfig,
		KrbCCache:         settings.KrbCCache,
		SPN:               settings.KrbSpn,
		MessageEncryption: settings.WinRMMessageEncryption,
	}
}

func (c *ClientKerberos) Transport(endpoint *Endpoint) error {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()

	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	if err := c.clientRequest.Transport(endpoint); err != nil {
		return err
	}
	c.httpClient = &http.Client{Transport: c.transport}
	c.kerberosClient = nil
	c.resetSecurityContext()
	return nil
}

func (c *ClientKerberos) Post(clt *Client, request *soap.SoapMessage) (string, error) {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()

	if c.httpClient == nil {
		return "", errors.New("kerberos transport is not initialized")
	}
	kerberosClient, err := c.getKerberosClient()
	if err != nil {
		return "", err
	}
	if c.MessageEncryption {
		return c.postEncrypted(clt.url, []byte(request.String()), kerberosClient)
	}
	return c.postAuthenticated(clt.url, []byte(request.String()), kerberosClient)
}

func (c *ClientKerberos) getKerberosClient() (*client.Client, error) {
	if c.kerberosClient != nil {
		return c.kerberosClient, nil
	}
	cfg, err := config.Load(c.KrbConf)
	if err != nil {
		return nil, fmt.Errorf("load Kerberos configuration %q: %w", c.KrbConf, err)
	}

	if c.KrbCCache != "" {
		cacheBytes, err := os.ReadFile(c.KrbCCache)
		if err != nil {
			return nil, fmt.Errorf("read Kerberos credential cache %q: %w", c.KrbCCache, err)
		}
		cache := new(credentials.CCache)
		if err := cache.Unmarshal(cacheBytes); err != nil {
			return nil, fmt.Errorf("parse Kerberos credential cache %q: %w", c.KrbCCache, err)
		}
		c.kerberosClient, err = client.NewFromCCache(cache, cfg, client.DisablePAFXFAST(true))
		if err != nil {
			return nil, fmt.Errorf("create Kerberos client from credential cache: %w", err)
		}
	} else {
		c.kerberosClient = client.NewWithPassword(
			c.Username,
			c.Realm,
			c.Password,
			cfg,
			client.DisablePAFXFAST(true),
			client.AssumePreAuthentication(true),
		)
	}
	return c.kerberosClient, nil
}

func (c *ClientKerberos) postAuthenticated(endpoint string, body []byte, kerberosClient *client.Client) (string, error) {
	req, err := http.NewRequestWithContext(stdcontext.Background(), "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create Kerberos request: %w", err)
	}
	setWinRMHeaders(req, "application/soap+xml;charset=UTF-8", len(body))
	if err := spnego.SetSPNEGOHeader(kerberosClient, req, c.SPN); err != nil {
		return "", fmt.Errorf("set SPNEGO header: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send Kerberos request: %w", err)
	}
	defer resp.Body.Close()
	return readKerberosSOAPResponse(resp)
}

func (c *ClientKerberos) postEncrypted(endpoint string, body []byte, kerberosClient *client.Client) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.ensureSecurityContext(endpoint, kerberosClient); err != nil {
			return "", err
		}
		encryptedBody, err := c.messageEncryption.encrypt(body)
		if err != nil {
			return "", err
		}
		req, err := http.NewRequestWithContext(stdcontext.Background(), "POST", endpoint, bytes.NewReader(encryptedBody))
		if err != nil {
			return "", fmt.Errorf("create encrypted Kerberos request: %w", err)
		}
		setWinRMHeaders(req, c.messageEncryption.contentType(), len(encryptedBody))
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("send encrypted Kerberos request: %w", err)
		}
		responseBody, err := func() (string, error) {
			defer resp.Body.Close()
			return c.readEncryptedResponse(resp)
		}()
		if err == nil {
			return responseBody, nil
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized || attempt != 0 {
			return "", err
		}

		// WinRM keeps authentication state on the HTTP connection. If the
		// keep-alive connection was replaced, establish a fresh GSS context
		// and replay this request once with a newly wrapped body.
		c.resetSecurityContext()
	}
	return "", errors.New("kerberos encrypted request retry exhausted")
}

func (c *ClientKerberos) readEncryptedResponse(resp *http.Response) (string, error) {
	if resp == nil {
		return "", errors.New("kerberos response is nil")
	}
	if resp.Body == nil {
		return "", errors.New("kerberos response body is nil")
	}
	if resp.StatusCode != http.StatusOK {
		responseBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("kerberos request returned HTTP %d; read response: %w", resp.StatusCode, readErr)
		}
		return "", fmt.Errorf("kerberos request returned HTTP %d: %s", resp.StatusCode, responseBody)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), fmt.Sprintf(`protocol="%s"`, c.messageEncryption.protocolString)) {
		responseBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", readErr
		}
		return "", fmt.Errorf("kerberos message encryption was required but the response was not encrypted: content type %q, body %q", resp.Header.Get("Content-Type"), responseBody)
	}
	decrypted, err := c.messageEncryption.decryptResponse(resp)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func (c *ClientKerberos) resetSecurityContext() {
	c.securityContext = nil
	c.messageEncryption = nil
}

func (c *ClientKerberos) ensureSecurityContext(endpoint string, kerberosClient *client.Client) error {
	if c.securityContext != nil && c.messageEncryption != nil {
		return nil
	}
	context, token, err := newKerberosInitiatorContext(kerberosClient, c.SPN)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(stdcontext.Background(), "POST", endpoint, nil)
	if err != nil {
		return fmt.Errorf("create Kerberos negotiation request: %w", err)
	}
	setWinRMHeaders(req, "application/soap+xml;charset=UTF-8", 0)
	req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send Kerberos negotiation request: %w", err)
	}
	if resp.Body == nil {
		return errors.New("kerberos negotiation response body is nil")
	}
	defer resp.Body.Close()
	responseToken, tokenErr := negotiateResponseToken(resp.Header.Values("WWW-Authenticate"))
	_, bodyErr := io.ReadAll(resp.Body)
	if bodyErr != nil {
		return fmt.Errorf("read Kerberos negotiation response: %w", bodyErr)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kerberos negotiation returned HTTP %d", resp.StatusCode)
	}
	if tokenErr != nil {
		return tokenErr
	}
	if err := context.accept(responseToken); err != nil {
		return err
	}
	messageEncryption, err := newWinRMMessageEncryption("kerberos", context)
	if err != nil {
		return err
	}
	c.securityContext = context
	c.messageEncryption = messageEncryption
	return nil
}

func negotiateResponseToken(headers []string) ([]byte, error) {
	for _, header := range headers {
		for _, challenge := range strings.Split(header, ",") {
			fields := strings.Fields(strings.TrimSpace(challenge))
			if len(fields) != 2 || (!strings.EqualFold(fields[0], "Negotiate") && !strings.EqualFold(fields[0], "Kerberos")) {
				continue
			}
			token, err := base64.StdEncoding.DecodeString(fields[1])
			if err != nil {
				return nil, fmt.Errorf("decode Kerberos Negotiate response: %w", err)
			}
			return token, nil
		}
	}
	return nil, errors.New("kerberos negotiation response did not include a Negotiate or Kerberos token")
}

func readKerberosSOAPResponse(resp *http.Response) (string, error) {
	if resp == nil {
		return "", errors.New("kerberos response is nil")
	}
	if resp.Body == nil {
		return "", errors.New("kerberos response body is nil")
	}
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kerberos request returned HTTP %d: %s", resp.StatusCode, responseBody)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/soap+xml") {
		return "", fmt.Errorf("invalid Kerberos response content type %q", resp.Header.Get("Content-Type"))
	}
	return string(responseBody), nil
}
