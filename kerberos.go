package winrm

import (
    "net"
    "net/http"
    "net/url"

    "github.com/dpotapov/go-spnego"
    "github.com/masterzen/winrm/soap"
)

// ClientKerberos provides a transport via Kerberos
type ClientKerberos struct {
    clientRequest
}

// Transport creates the wrapped Kerberos transport
func (c *ClientKerberos) Transport(endpoint *Endpoint) error {
    c.clientRequest.Transport(endpoint)
    c.clientRequest.transport = &spnego.Transport{}
    return nil
}

// Post make post to the winrm soap service (forwarded to clientRequest implementation)
func (c ClientKerberos) Post(client *Client, request *soap.SoapMessage) (string, error) {
    return c.clientRequest.Post(client, request)
}

//NewClientKerberosWithDial NewClientKerberosWithDial
func NewClientKerberosWithDial(dial func(network, addr string) (net.Conn, error)) *ClientKerberos {
    return &ClientKerberos{
        clientRequest{
            dial: dial,
        },
    }
}

//NewClientKerberosWithProxyFunc NewClientKerberosWithProxyFunc
func NewClientKerberosWithProxyFunc(proxyfunc func(req *http.Request) (*url.URL, error)) *ClientKerberos {
    return &ClientKerberos{
        clientRequest{
            proxyfunc: proxyfunc,
        },
    }
}

