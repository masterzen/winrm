package winrm

import (
	"github.com/masterzen/winrm/soap"
	. "gopkg.in/check.v1"
	"launchpad.net/gwacl/fork/tls"
)

var key = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCc3TmlGZVwcwgK
qS6V1FmyGuNbeSG657pArXvVAeKq8usLXjPr6RmjIRzV7soS4PQdqSIVtSUBAFlk
2S0YLMGuPXufwwaxeIgW+qTJLP9oF6U13NIDcswIM/2EvdgaBfjNO71KoON3qzOW
KmuTlTL9ifyF+9sLiR2FWnXq408u5B4/1aAe9xOel/2AyzGjiesQt1Q1MsvKFs3d
/1fxuf550jV8krVKDRVFZyARZfZ2qT02hxqqp0j7H0k06KQ8ljfP6mx0B3Nx0M71
TQ6Ni+HFIIiuO448cu6fZw97O83qGkNDmXV130ZwlKXeby6E8CBK+JwmtSWd0w+B
+ex7oGGJAgMBAAECggEAL5mV93qW9WOCqjGCeGbSvRAZs9VDHgNZamz6ab3DuZoz
JuT0Hn9Cj1Tp+iUW3rmyehmrxSiNzQr9FXQtketq7mOr0uQMcOgha8+tF3r3GfAq
6vhSJke8kDSuloxBOkxbnnOlUjMWM2cZJVVEBam9qmAn58RwSMTX13KG27sUeSa4
Lvl0SiCfxl99NBHHNXWutJIuBWP+dCejbiK0xb7thuIBLN4T50JHAfMExeU51YmD
OUrwYVTU1FozeJcQuQ5cA3fBkfIzhrFmn16gGUKdy9L1UzBfU+skVxycXLr/2AtI
gO+W33tHzxuPluRYBQNgfxxnv9ajUc/2EjztGXLJLQKBgQDQBbC5bMr8Y3NcB+6V
lNZykniPBwrTD+4lGBh30rQKeKd5mNMHadPVORBK/FliSvioDS8RwtKz8Iq5HGTh
5wRW2+5cytznHoPH/s3AxxA3Jw0A4xt3/+xFsBQITRoB3IxptffRak4uQsWR46RM
l8ItBZ3FvskTQTWULQ/M4XvpZwKBgQDBCv75hXQW1P6cMzHcs4MUeADe2qM+LHRh
y7So/oyZMJvlukhM6gR385jzRRcWH7n+5o7dLGaVJ6I5Hg5RMbspIfgOqRrTD/o5
yZF5XSYw2UFhldYMlADHuSF5jM5puv/odQEykjasMo3eYnhod7k9UksOrrECdUnf
99hActFXjwKBgQCT9vg1bIUV8Udk9t9l1nCTHkxSsBeq+XHTQMhmsqENsbSucV3p
sATVbbmBHO4XVGx6XKZWY9Wr2DVUZjX72W7kuZtatZFbdAEYiM2hifamxEgjkWdA
e/F7wDr/jJgrKs1Vg/G6K3tgvG37z4hWUrvzekM3HPW5lHCf7U2H1ftlkQKBgBvb
K1n0UQEucSM3G/3eBY9BldaStDW3kn++Nm6gdMdyRTzMObynlEd+5lZMZP1zTJKk
0H7H9nGVi4o0dRpwU7KmzTXIXy+PwarvFEfwEh/Aaffb+ExOWyJ264avs+V774uq
vqZ+hNcqYGBz0y44AIoBwwT2XmKdbDCegh0itGSvAoGAGWgwqJ4pCEmW/EAMjg8Q
TfiXBqrBINgPISGIV2ASTIHb4n2k2yEsTJiODk85M00DtkCjqWR8fa/F8N01Rwnf
nJH+lDaWkqbWyYanRl2LgC6vuHcu1d5GjxfCzGgMnBhXi7YZjPaTZaDC5poaTyFW
S5GRL8NLTmLBxDYXWzcwlTw=
-----END PRIVATE KEY-----
`[1:]

var cert = `
-----BEGIN CERTIFICATE-----
MIIDGzCCAgMCAgPoMA0GCSqGSIb3DQEBBQUAMCgxJjAkBgNVBAMUHW1hYXNjb250
cm9sbGVyQE1hYXNDb250cm9sbGVyMB4XDTE1MDcxMDEzMjY0N1oXDTI1MDcwNzEz
MjY0N1owKDEmMCQGA1UEAxQdbWFhc2NvbnRyb2xsZXJATWFhc0NvbnRyb2xsZXIw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc3TmlGZVwcwgKqS6V1Fmy
GuNbeSG657pArXvVAeKq8usLXjPr6RmjIRzV7soS4PQdqSIVtSUBAFlk2S0YLMGu
PXufwwaxeIgW+qTJLP9oF6U13NIDcswIM/2EvdgaBfjNO71KoON3qzOWKmuTlTL9
ifyF+9sLiR2FWnXq408u5B4/1aAe9xOel/2AyzGjiesQt1Q1MsvKFs3d/1fxuf55
0jV8krVKDRVFZyARZfZ2qT02hxqqp0j7H0k06KQ8ljfP6mx0B3Nx0M71TQ6Ni+HF
IIiuO448cu6fZw97O83qGkNDmXV130ZwlKXeby6E8CBK+JwmtSWd0w+B+ex7oGGJ
AgMBAAGjVDBSMDgGA1UdEQQxMC+gLQYKKwYBBAGCNxQCA6AfDB1tYWFzY29udHJv
bGxlckBNYWFzQ29udHJvbGxlcjAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAjANBgkq
hkiG9w0BAQUFAAOCAQEAeoK0Ndddv346JBZFWpsLIeygxtFLMtKa3A4DMYfTO2Ht
STiEKe4027ptQ/uMkYVEHHHD/Jr3Nz0/qOciGu7r7Q+rDQlJRyC4VgNhieniSjck
8coWjg65xuZHh/SePQK9eatOHTYQIU4CoQhk0kPtNdsF70iaE8DqsFT30gEEYHnG
BHTNtF0jH8vw32u0fYhfxYZSaQEycQ5bT46IHnU2RZMYSNiiSf9jj8kHG3s9Xu2r
RuoV7MsL0ju6DgUydp40rYGFL3lpzlSvPKATHB6zcOE9pB8GD3z7Lp4b4Anz6Jlu
QkGuzNBHsEJlM3/pXqUpnP6kvlwZfIhQaefNnYhnmQ==
-----END CERTIFICATE-----
`[1:]

var keyBytes = []byte(key)
var certBytes = []byte(cert)

func (s *WinRMSuite) TestNewClient(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")

	c.Assert(err, IsNil)
	c.Assert(client.url, Equals, "http://localhost:5985/wsman")
	c.Assert(client.username, Equals, "Administrator")
	c.Assert(client.password, Equals, "v3r1S3cre7")
}

func (s *WinRMSuite) TestNewClientInvalidTransport(c *C) {
	_, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "", "")

	c.Assert(err, ErrorMatches, "Invalid transport type")
}

func (s *WinRMSuite) TestNewClientBasicAuthNoUserAndPassword(c *C) {
	var basicAuthTests = []struct {
		username string
		password string
	}{
		{"", ""},
		{"Administrator", ""},
		{"", "v3r1S3cre7"},
	}

	for _, k := range basicAuthTests {
		_, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, k.username, k.password)

		c.Assert(err, ErrorMatches, "Invalid transport type")
	}
}

func (s *WinRMSuite) TestNewClientCertAuth(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5986, HTTPS: true, Cert: &certBytes, Key: &keyBytes}, "", "")

	c.Assert(err, IsNil)
	c.Assert(client.url, Equals, "https://localhost:5986/wsman")
	c.Assert(client.username, Equals, "")
	c.Assert(client.password, Equals, "")
	c.Assert(client.useHTTPS, Equals, true)

	transport := client.transport.TLSClientConfig.Certificates

	certPool, err := tls.X509KeyPair(certBytes, keyBytes)

	c.Assert(err, IsNil)

	c.Assert(transport[0].Certificate, DeepEquals, certPool.Certificate)

	c.Assert(transport[0].PrivateKey, DeepEquals, certPool.PrivateKey)

}

func (s *WinRMSuite) TestNewClientCertAuthInvalidProtocol(c *C) {
	_, err := NewClient(&Endpoint{Host: "localhost", Port: 5986, HTTPS: false, Cert: &certBytes, Key: &keyBytes}, "", "")

	c.Assert(err, ErrorMatches, "Invalid protocol for this transport type \\(CertAuth\\). Expected https")
}

func (s *WinRMSuite) TestNewClientCertAuthParseKeyPairFailure(c *C) {
	invalid_key := []byte("AAA")
	_, err := NewClient(&Endpoint{Host: "localhost", Port: 5986, HTTPS: true, Cert: &certBytes, Key: &invalid_key}, "", "")

	c.Assert(err, ErrorMatches, "Error parsing keypair: crypto/tls: failed to parse key PEM data")
}

func (s *WinRMSuite) TestClientCreateShell(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		c.Assert(message.String(), Contains, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create")
		return createShellResponse, nil
	}

	shell, err := client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(shell.ShellId, Equals, "67A74734-DD32-4F10-89DE-49A060483810")
}

func (s *WinRMSuite) TestClientCreateShellCertAuth(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5986, HTTPS: true, Cert: &certBytes, Key: &keyBytes}, "", "")
	c.Assert(err, IsNil)
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		c.Assert(message.String(), Contains, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create")
		return createShellResponse, nil
	}

	shell, err := client.CreateShell()
	c.Assert(err, IsNil)
	c.Assert(shell.ShellId, Equals, "67A74734-DD32-4F10-89DE-49A060483810")
}
