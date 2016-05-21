package winrm

import (
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/masterzen/winrm/soap"
	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestNewClient(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")

	c.Assert(err, IsNil)
	c.Assert(client.url, Equals, "http://localhost:5985/wsman")
	c.Assert(client.username, Equals, "Administrator")
	c.Assert(client.password, Equals, "v3r1S3cre7")
}

func (s *WinRMSuite) TestClientCreateShell(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		c.Assert(message.String(), Contains, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create")
		return createShellResponse, nil
	}

	shell, _ := client.CreateShell()
	c.Assert(shell.ID, Equals, "67A74734-DD32-4F10-89DE-49A060483810")
}

func (s *WinRMSuite) TestReplaceTransportWithDecorator(c *C) {
	var myrt rtfunc = func(req *http.Request) (*http.Response, error) {
		req.Body.Close()
		header := http.Header{"Content-Type": {"application/soap+xml; charset=UTF-8"}}
		return &http.Response{StatusCode: 500, Header: header, Body: ioutil.NopCloser(strings.NewReader(""))}, nil
	}

	params := DefaultParameters
	params.TransportDecorator = func(*http.Transport) http.RoundTripper { return myrt }

	client, err := NewClientWithParameters(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "password", params)
	c.Assert(err, IsNil)
	_, err = client.http(client, soap.NewMessage())
	c.Assert(err.Error(), Equals, "http error: 500 - ")
}

type rtfunc func(*http.Request) (*http.Response, error)

func (f rtfunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
