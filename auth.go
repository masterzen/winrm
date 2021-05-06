package winrm

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/masterzen/winrm/soap"
)

//ClientAuthRequest ClientAuthRequest
type ClientAuthRequest struct {
	transport http.RoundTripper
	dial      func(network, addr string) (net.Conn, error)
}

//Transport Transport
func (c *ClientAuthRequest) Transport(endpoint *Endpoint) error {
	cert, err := tls.X509KeyPair(endpoint.Cert, endpoint.Key)
	if err != nil {
		return err
	}

	dial := (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial

	if c.dial != nil {
		dial = c.dial
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: endpoint.Insecure,
			Certificates:       []tls.Certificate{cert},
		},
		Dial:                  dial,
		ResponseHeaderTimeout: endpoint.Timeout,
	}

	if endpoint.CACert != nil && len(endpoint.CACert) > 0 {
		certPool, err := readCACerts(endpoint.CACert)
		if err != nil {
			return err
		}

		transport.TLSClientConfig.RootCAs = certPool
	}

	c.transport = transport

	return nil
}


//Post Post
func (c ClientAuthRequest) Post(client *Client, request *soap.SoapMessage) (string, error) {
	httpClient := &http.Client{Transport: c.transport}

	req, err := http.NewRequest("POST", client.url, strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("impossible to create http request %s", err)
	}

	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	req.Header.Set("Authorization", "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("unknown error %s", err)
	}

	// error in case on incorrect exit code
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http unexpected status: %s", resp.Status)
	}

	body, err := ParseSoapResponse(resp)
	if err != nil {
		return "", fmt.Errorf("http response error: %d - %s", resp.StatusCode, err.Error())
	}

	return body, err
}

//NewClientAuthRequestWithDial NewClientAuthRequestWithDial
func NewClientAuthRequestWithDial(dial func(network, addr string) (net.Conn, error)) *ClientAuthRequest {
	return &ClientAuthRequest{
		dial: dial,
	}
}
