package winrm

import (
	"net/http"

	"github.com/Azure/go-ntlmssp"
	"github.com/masterzen/winrm/soap"
)

// ClientNTLM provides a transport via NTLMv2
type ClientNTLM struct {
	clientRequest
}

// Transport creates the wrapped NTLM transport
func (c *ClientNTLM) Transport(endpoint *Endpoint) (http.RoundTripper, error) {
	c.clientRequest.Transport(endpoint)
	transport := &ntlmssp.Negotiator{RoundTripper: c.clientRequest.transport}
	c.clientRequest.transport = transport
	return transport, nil
}

// Post make post to the winrm soap service (forwarded to clientRequest implementation)
func (c ClientNTLM) Post(client *Client, request *soap.SoapMessage) (string, error) {
	return c.clientRequest.Post(client, request)
}
