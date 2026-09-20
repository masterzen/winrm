package winrm

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"

	"net"
	"time"

	. "gopkg.in/check.v1"
)

func ntlmChallengeMessage(serverChallenge [8]byte) []byte {
	const flags = 1<<0 | 1<<4 | 1<<5 | 1<<29 | 1<<30
	msg := make([]byte, 48)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	copy(msg[24:32], serverChallenge[:])
	return msg
}

func isNTLMNegotiateMessage(token []byte) bool {
	return len(token) >= 12 && binary.LittleEndian.Uint32(token[8:12]) == 1
}

func (s *WinRMSuite) TestHttpNTLMRequest(c *C) {
	ts, host, port, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		_, _ = w.Write([]byte(response))
	}))
	c.Assert(err, IsNil)
	defer ts.Close()
	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := *DefaultParameters
	params.TransportDecorator = func() Transporter { return &ClientNTLM{} }
	client, err := NewClientWithParameters(endpoint, "test", "test", &params)

	c.Assert(err, IsNil)
	shell, err := client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(shell.id, Equals, "67A74734-DD32-4F10-89DE-49A060483810")
}

func (s *WinRMSuite) TestHttpNTLMViaCustomDialerRequest(c *C) {
	normalDialer := (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial
	usedCustomDialer := false
	dial := func(network, addr string) (net.Conn, error) {
		usedCustomDialer = true
		return normalDialer(network, addr)
	}

	ts, host, port, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		_, _ = w.Write([]byte(response))
	}))
	c.Assert(err, IsNil)
	defer ts.Close()
	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := *DefaultParameters
	params.TransportDecorator = func() Transporter { return NewClientNTLMWithDial(dial) }
	client, err := NewClientWithParameters(endpoint, "test", "test", &params)
	c.Assert(err, IsNil)
	_, err = client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(usedCustomDialer, Equals, true)
}

// TestNTLMSessionReusedAcrossRequests checks the case the sealing transport
// exists for: the 3-leg NTLM handshake (401 -> 401+challenge -> 200) only
// happens once per connection, and later requests reuse the negotiated
// session (no Authorization header, no re-challenge).
func (s *WinRMSuite) TestNTLMSessionReusedAcrossRequests(c *C) {
	var authenticated bool
	var total, negotiations int
	ts, host, port, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total++
		auth := r.Header.Get("Authorization")
		switch {
		case auth == "" && !authenticated:
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasPrefix(auth, "NTLM "):
			negotiations++
			token, decErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "NTLM "))
			c.Assert(decErr, IsNil)
			if isNTLMNegotiateMessage(token) {
				challenge := ntlmChallengeMessage([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
				w.Header().Set("Www-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(challenge))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			authenticated = true
			w.Header().Set("Content-Type", "application/soap+xml")
			fmt.Fprintln(w, createShellResponse)
		default:
			// already authenticated: a reused, sealed request should carry no Authorization header
			c.Assert(auth, Equals, "")
			w.Header().Set("Content-Type", "application/soap+xml")
			fmt.Fprintln(w, createShellResponse)
		}
	}))
	c.Assert(err, IsNil)
	defer ts.Close()
	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := *DefaultParameters
	params.TransportDecorator = func() Transporter { return &ClientNTLM{} }
	client, err := NewClientWithParameters(endpoint, "test", "test", &params)
	c.Assert(err, IsNil)

	shell, err := client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(shell.id, Equals, "67A74734-DD32-4F10-89DE-49A060483810")
	c.Assert(total, Equals, 3)
	c.Assert(negotiations, Equals, 2)

	shell, err = client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(shell.id, Equals, "67A74734-DD32-4F10-89DE-49A060483810")
	c.Assert(total, Equals, 4)
	c.Assert(negotiations, Equals, 2)
}

// TestNTLMReauthenticatesAfterStaleSession checks that a 401 on a sealed
// request is treated as a stale session.
// client drops its cached keys and transparently redoes the full handshake.
func (s *WinRMSuite) TestNTLMReauthenticatesAfterStaleSession(c *C) {
	var authenticated bool
	var staled bool
	var total, negotiations int
	ts, host, port, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		total++
		auth := r.Header.Get("Authorization")
		switch {
		case auth == "" && !authenticated:
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasPrefix(auth, "NTLM "):
			negotiations++
			token, decErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "NTLM "))
			c.Assert(decErr, IsNil)
			if isNTLMNegotiateMessage(token) {
				challenge := ntlmChallengeMessage([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
				w.Header().Set("Www-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(challenge))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			authenticated = true
			w.Header().Set("Content-Type", "application/soap+xml")
			fmt.Fprintln(w, createShellResponse)
		case !staled:
			// pretend the session expired on the server side
			staled = true
			authenticated = false
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.Header().Set("Content-Type", "application/soap+xml")
			fmt.Fprintln(w, createShellResponse)
		}
	}))
	c.Assert(err, IsNil)
	defer ts.Close()
	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)

	params := *DefaultParameters
	params.TransportDecorator = func() Transporter { return &ClientNTLM{} }
	client, err := NewClientWithParameters(endpoint, "test", "test", &params)
	c.Assert(err, IsNil)

	_, err = client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(total, Equals, 3)
	c.Assert(negotiations, Equals, 2)

	shell, err := client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(shell.id, Equals, "67A74734-DD32-4F10-89DE-49A060483810")
	c.Assert(total, Equals, 7)
	c.Assert(negotiations, Equals, 4)
}
