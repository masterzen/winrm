package winrm

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/masterzen/winrm/soap"
	"io/ioutil"
)

var soapXML = "application/soap+xml"

// parse func reads the response body and return it as a string
func ParseSoapResponse(response *http.Response) (string, error) {

	contentType := response.Header.Get("Content-Type")
	// if we received the content we expected
	if strings.Contains(contentType, soapXML) {
		body, err := ioutil.ReadAll(response.Body)
		defer func() {
			// defer can modify the returned value before
			// it is actually passed to the calling statement
			if errClose := response.Body.Close(); errClose != nil && err == nil {
				err = errClose
			}
		}()
		if err != nil {
			return "", fmt.Errorf("error while reading request body %s", err)
		}

		return string(body), nil
	}

	return "", fmt.Errorf("invalid content type: %s", contentType)
}

type clientRequest struct {
	transport http.RoundTripper
}

func (c *clientRequest) Transport(endpoint *Endpoint) error {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: endpoint.Insecure,
			ServerName:         endpoint.TLSServerName,
		},
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
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

// Post make post to the winrm soap service
func (c clientRequest) Post(client *Client, request *soap.SoapMessage) (string, error) {
	httpClient := &http.Client{Transport: c.transport}

	req, err := http.NewRequest("POST", client.url, strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("impossible to create http request %s", err)
	}
	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	req.SetBasicAuth(client.username, client.password)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("unknown error %s", err)
	}

	// error in case of incorrect exit code
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http unexpected status: %s", resp.Status)
	}

	body, err := ParseSoapResponse(resp)
	if err != nil {
		return "", fmt.Errorf("http response error: %d - %s", resp.StatusCode, err.Error())
	}

	return body, err
}
