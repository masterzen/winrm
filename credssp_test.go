package winrm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestCredSSPTSRequestRoundTrip(c *C) {
	original := tsRequest{
		Version:     credSSPDefaultVersion,
		NegoTokens:  []negoDataItem{{NegoToken: []byte("nego-1")}, {NegoToken: []byte("nego-2")}},
		AuthInfo:    []byte("auth-info"),
		PubKeyAuth:  []byte("pub-key"),
		ClientNonce: []byte("nonce"),
	}

	encoded, err := marshalTSRequest(original)
	c.Assert(err, IsNil)

	decoded, err := unmarshalTSRequest(encoded)
	c.Assert(err, IsNil)
	c.Assert(decoded.Version, Equals, original.Version)
	c.Assert(decoded.NegoTokens, DeepEquals, original.NegoTokens)
	c.Assert(decoded.AuthInfo, DeepEquals, original.AuthInfo)
	c.Assert(decoded.PubKeyAuth, DeepEquals, original.PubKeyAuth)
	c.Assert(decoded.ClientNonce, DeepEquals, original.ClientNonce)
}

func (s *WinRMSuite) TestCredSSPCredentialsRoundTrip(c *C) {
	encoded, err := marshalCredentials("DOMAIN", "administrator", "s3cr3t")
	c.Assert(err, IsNil)

	var creds tsCredentials
	rest, err := asn1.Unmarshal(encoded, &creds)
	c.Assert(err, IsNil)
	c.Assert(len(rest), Equals, 0)
	c.Assert(creds.CredType, Equals, credSSPAuthTypePassword)

	var passwordCreds tspasswordCreds
	rest, err = asn1.Unmarshal(creds.Credentials, &passwordCreds)
	c.Assert(err, IsNil)
	c.Assert(len(rest), Equals, 0)
	// Credentials must be UTF-16LE encoded for Windows.
	c.Assert(passwordCreds.DomainName, DeepEquals, utf16LEBytes("DOMAIN"))
	c.Assert(passwordCreds.UserName, DeepEquals, utf16LEBytes("administrator"))
	c.Assert(passwordCreds.Password, DeepEquals, utf16LEBytes("s3cr3t"))
	// Sanity check the encoding: ASCII chars become byte + 0x00.
	c.Assert(passwordCreds.DomainName[:4], DeepEquals, []byte{'D', 0x00, 'O', 0x00})
}

func (s *WinRMSuite) TestCredSSPTrailerLengthTable(c *C) {
	encryption, err := NewEncryption("credssp")
	c.Assert(err, IsNil)

	testCases := []struct {
		name       string
		messageLen int
		cipher     string
		expected   int
	}{
		{name: "gcm", messageLen: 31, cipher: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", expected: 16},
		{name: "rc4", messageLen: 31, cipher: "TLS_RSA_WITH_RC4_128_SHA", expected: 20},
		{name: "3des", messageLen: 31, cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", expected: 25},
		{name: "aes-cbc-sha256", messageLen: 31, cipher: "TLS_RSA_WITH_AES_128_CBC_SHA256", expected: 33},
		{name: "aes-cbc-sha384", messageLen: 31, cipher: "TLS_RSA_WITH_AES_256_CBC_SHA384", expected: 49},
	}

	for _, tc := range testCases {
		c.Assert(encryption.getCredSSPTrailerLength(tc.messageLen, tc.cipher), Equals, tc.expected, Commentf(tc.name))
	}
}

func (s *WinRMSuite) TestCredSSPBuildDecryptRoundTrip(c *C) {
	clientConn, serverConn, err := newCredSSPTLSHarness()
	c.Assert(err, IsNil)

	encryption, err := NewEncryption("credssp")
	c.Assert(err, IsNil)
	encryption.tlsConn = clientConn.tlsConn
	encryption.credsspConn = clientConn.memConn
	encryption.timeout = 5 * time.Second

	request := []byte("create shell request")
	wrappedRequest, err := encryption.buildCredSSPMessage(request, "host")
	c.Assert(err, IsNil)
	c.Assert(len(wrappedRequest) > 4, Equals, true)

	if err := serverConn.memConn.pushIncoming(wrappedRequest[4:]); err != nil {
		c.Fatal(err)
	}
	receivedRequest := make([]byte, len(request))
	n, err := serverConn.tlsConn.Read(receivedRequest)
	c.Assert(err, IsNil)
	c.Assert(receivedRequest[:n], DeepEquals, request)

	response := []byte("create shell response")
	_, err = serverConn.tlsConn.Write(response)
	c.Assert(err, IsNil)
	serverCiphertext, err := serverConn.memConn.popOutgoing(5 * time.Second)
	c.Assert(err, IsNil)
	serverCiphertext = serverConn.memConn.drainOutgoing(serverCiphertext)

	cipherName := tls.CipherSuiteName(clientConn.tlsConn.ConnectionState().CipherSuite)
	trailer := encryption.getCredSSPTrailerLength(len(response), cipherName)
	payload := make([]byte, 4+len(serverCiphertext))
	binary.LittleEndian.PutUint32(payload[:4], uint32(trailer))
	copy(payload[4:], serverCiphertext)

	decrypted, err := encryption.decryptCredsspMessage(payload, "host", len(response))
	c.Assert(err, IsNil)
	c.Assert(decrypted, DeepEquals, response)
}

// fakeSecurityContext is a reversible stand-in for *ntlmssp.SecuritySession so
// the CredSSP wire framing can be asserted without a full NTLM handshake.
type fakeSecurityContext struct {
	signature []byte
}

func (f *fakeSecurityContext) Wrap(b []byte) ([]byte, []byte, error) {
	sealed := make([]byte, len(b))
	for i := range b {
		sealed[i] = b[i] ^ 0xAA
	}
	return sealed, append([]byte(nil), f.signature...), nil
}

func (f *fakeSecurityContext) Unwrap(b, signature []byte) ([]byte, error) {
	if !bytes.Equal(signature, f.signature) {
		return nil, errors.New("signature mismatch")
	}
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0xAA
	}
	return out, nil
}

// TestCredSSPWrapWireFormat guards the MS-CSSP framing: signature (16 bytes)
// immediately followed by sealed data, with no 4-byte length prefix.
func (s *WinRMSuite) TestCredSSPWrapWireFormat(c *C) {
	signature := bytes.Repeat([]byte{0x11}, ntlmSignatureLength)
	ctx := &fakeSecurityContext{signature: signature}
	payload := []byte("public-key-info-payload")

	wrapped, err := wrapCredSSPData(ctx, payload)
	c.Assert(err, IsNil)

	// No length prefix: exactly signature + sealed, and RC4-style sealing keeps
	// the sealed length equal to the plaintext length.
	c.Assert(len(wrapped), Equals, ntlmSignatureLength+len(payload))
	c.Assert(wrapped[:ntlmSignatureLength], DeepEquals, signature)

	expectedSealed := make([]byte, len(payload))
	for i := range payload {
		expectedSealed[i] = payload[i] ^ 0xAA
	}
	c.Assert(wrapped[ntlmSignatureLength:], DeepEquals, expectedSealed)

	// The signature must be at the very front; a stray length prefix would put
	// the first signature byte at offset 4 instead of 0.
	c.Assert(wrapped[0], Equals, byte(0x11))

	out, err := unwrapCredSSPData(ctx, wrapped)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, payload)
}

func (s *WinRMSuite) TestCredSSPUnwrapRejectsShortPayload(c *C) {
	ctx := &fakeSecurityContext{signature: bytes.Repeat([]byte{0x11}, ntlmSignatureLength)}
	_, err := unwrapCredSSPData(ctx, []byte{0x00, 0x01, 0x02})
	c.Assert(err, NotNil)
}

// TestCredSSPPubKeyAuthDirection guards the v2-v4 vs v5+ pubKeyAuth direction:
// pre-v5 the client sends the key unmodified and expects it back +1; v5+ uses
// distinct directional SHA-256 binding hashes.
func (s *WinRMSuite) TestCredSSPPubKeyAuthDirection(c *C) {
	pubKey := []byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82}

	clientPlain, expected := computePubKeyAuthPlaintext(4, nil, pubKey)
	c.Assert(clientPlain, DeepEquals, pubKey)

	wantExpected := append([]byte(nil), pubKey...)
	wantExpected[0]++
	c.Assert(expected, DeepEquals, wantExpected)
	// The input key must not be mutated in place.
	c.Assert(pubKey[0], Equals, byte(0x30))

	nonce := bytes.Repeat([]byte{0x07}, 32)
	clientHash, serverHash := computePubKeyAuthPlaintext(credSSPDefaultVersion, nonce, pubKey)
	c.Assert(len(clientHash), Equals, 32)
	c.Assert(len(serverHash), Equals, 32)
	c.Assert(bytes.Equal(clientHash, serverHash), Equals, false)
	c.Assert(clientHash, DeepEquals, credSSPBindingHash(credSSPClientBindingLabel, nonce, pubKey))
	c.Assert(serverHash, DeepEquals, credSSPBindingHash(credSSPServerBindingLabel, nonce, pubKey))
}

// TestCredSSPDecryptSpansMultipleRecords guards decrypting a chunk whose
// plaintext spans several TLS records (finding: a single Read returns short).
func (s *WinRMSuite) TestCredSSPDecryptSpansMultipleRecords(c *C) {
	clientConn, serverConn, err := newCredSSPTLSHarness()
	c.Assert(err, IsNil)

	encryption, err := NewEncryption("credssp")
	c.Assert(err, IsNil)
	encryption.tlsConn = clientConn.tlsConn
	encryption.credsspConn = clientConn.memConn
	encryption.timeout = 5 * time.Second

	// Larger than a single 16 KB TLS record to force multiple records.
	response := bytes.Repeat([]byte("ABCDEFGH"), 5000)
	_, err = serverConn.tlsConn.Write(response)
	c.Assert(err, IsNil)

	sealedFirst, err := serverConn.memConn.popOutgoing(5 * time.Second)
	c.Assert(err, IsNil)
	sealed := serverConn.memConn.drainOutgoing(sealedFirst)

	cipherName := tls.CipherSuiteName(clientConn.tlsConn.ConnectionState().CipherSuite)
	trailer := encryption.getCredSSPTrailerLength(len(response), cipherName)
	payload := make([]byte, 4+len(sealed))
	binary.LittleEndian.PutUint32(payload[:4], uint32(trailer))
	copy(payload[4:], sealed)

	decrypted, err := encryption.decryptCredsspMessage(payload, "host", len(response))
	c.Assert(err, IsNil)
	c.Assert(decrypted, DeepEquals, response)
}

// TestCredSSPDecryptTamperedFails ensures a modified ciphertext is rejected by
// the TLS integrity layer rather than returning corrupt plaintext.
func (s *WinRMSuite) TestCredSSPDecryptTamperedFails(c *C) {
	clientConn, serverConn, err := newCredSSPTLSHarness()
	c.Assert(err, IsNil)

	encryption, err := NewEncryption("credssp")
	c.Assert(err, IsNil)
	encryption.tlsConn = clientConn.tlsConn
	encryption.credsspConn = clientConn.memConn
	encryption.timeout = 2 * time.Second

	response := []byte("sensitive data payload")
	_, err = serverConn.tlsConn.Write(response)
	c.Assert(err, IsNil)

	sealedFirst, err := serverConn.memConn.popOutgoing(5 * time.Second)
	c.Assert(err, IsNil)
	sealed := serverConn.memConn.drainOutgoing(sealedFirst)

	// Corrupt the final ciphertext byte; TLS AEAD verification must fail.
	sealed[len(sealed)-1] ^= 0xFF

	cipherName := tls.CipherSuiteName(clientConn.tlsConn.ConnectionState().CipherSuite)
	trailer := encryption.getCredSSPTrailerLength(len(response), cipherName)
	payload := make([]byte, 4+len(sealed))
	binary.LittleEndian.PutUint32(payload[:4], uint32(trailer))
	copy(payload[4:], sealed)

	_, err = encryption.decryptCredsspMessage(payload, "host", len(response))
	c.Assert(err, NotNil)
}

// TestCredSSPFinalMessageIsSendOnly guards finding 3: the final authInfo message
// must not block or fail waiting for a server reply that never comes.
func (s *WinRMSuite) TestCredSSPFinalMessageIsSendOnly(c *C) {
	clientConn, _, err := newCredSSPTLSHarness()
	c.Assert(err, IsNil)

	ts, _, _, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	c.Assert(err, IsNil)
	defer ts.Close()

	client := &ClientCredSSP{
		httpClient: &http.Client{},
		endpoint:   &Endpoint{Timeout: 5 * time.Second},
		tlsConn:    clientConn.tlsConn,
		memConn:    clientConn.memConn,
	}

	err = client.sendTSRequestNoReply(ts.URL, tsRequest{
		Version:  credSSPDefaultVersion,
		AuthInfo: []byte("delegated-credentials"),
	})
	c.Assert(err, IsNil)
}

// TestCredSSPReplyRequiredFailsWithoutToken confirms the reply-required path
// still errors when no CredSSP token is returned, i.e. the send-only path above
// is genuinely necessary for the final message.
func (s *WinRMSuite) TestCredSSPReplyRequiredFailsWithoutToken(c *C) {
	clientConn, _, err := newCredSSPTLSHarness()
	c.Assert(err, IsNil)

	ts, _, _, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	c.Assert(err, IsNil)
	defer ts.Close()

	client := &ClientCredSSP{
		httpClient: &http.Client{},
		endpoint:   &Endpoint{Timeout: 5 * time.Second},
		tlsConn:    clientConn.tlsConn,
		memConn:    clientConn.memConn,
	}

	_, err = client.sendTSRequest(ts.URL, tsRequest{
		Version:    credSSPDefaultVersion,
		NegoTokens: []negoDataItem{{NegoToken: []byte("token")}},
	})
	c.Assert(err, NotNil)
}

// TestCredSSPResponseErrorCode guards that a server TSRequest carrying an
// NTSTATUS error code is surfaced instead of being ignored.
func (s *WinRMSuite) TestCredSSPResponseErrorCode(c *C) {
	c.Assert(credSSPResponseError(nil), IsNil)
	c.Assert(credSSPResponseError(&tsRequest{Version: credSSPDefaultVersion}), IsNil)

	// Use a real NTSTATUS whose high bit is set; this must round-trip through
	// ASN.1 (int64) on any platform, including 32-bit.
	encoded, err := marshalTSRequest(tsRequest{Version: credSSPDefaultVersion, ErrorCode: 0xC000006A})
	c.Assert(err, IsNil)
	decoded, err := unmarshalTSRequest(encoded)
	c.Assert(err, IsNil)

	err = credSSPResponseError(decoded)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Contains, "0xC000006A")
}

// TestCredSSPCertificatePublicKey guards that CredSSP binds against the PKCS#1
// RSAPublicKey encoding, not the full SubjectPublicKeyInfo (a mismatch here
// makes real Windows servers reject pubKeyAuth).
func (s *WinRMSuite) TestCredSSPCertificatePublicKey(c *C) {
	certificate, err := generateCredSSPTestCertificate()
	c.Assert(err, IsNil)

	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	c.Assert(err, IsNil)

	pkcs1, err := credSSPCertificatePublicKey(parsed)
	c.Assert(err, IsNil)

	rsaPub, ok := parsed.PublicKey.(*rsa.PublicKey)
	c.Assert(ok, Equals, true)
	c.Assert(pkcs1, DeepEquals, x509.MarshalPKCS1PublicKey(rsaPub))

	// It must NOT be the SubjectPublicKeyInfo (the previous, incorrect form).
	c.Assert(bytes.Equal(pkcs1, parsed.RawSubjectPublicKeyInfo), Equals, false)
	c.Assert(len(pkcs1) < len(parsed.RawSubjectPublicKeyInfo), Equals, true)
}

// TestNegotiateCredSSPVersion guards the version floor and the CVE-2018-0886
// minimum-version knob.
func (s *WinRMSuite) TestNegotiateCredSSPVersion(c *C) {
	v, err := negotiateCredSSPVersion(6, 8, 0)
	c.Assert(err, IsNil)
	c.Assert(v, Equals, 6)

	v, err = negotiateCredSSPVersion(6, 3, 0)
	c.Assert(err, IsNil)
	c.Assert(v, Equals, 3)

	_, err = negotiateCredSSPVersion(6, 1, 0)
	c.Assert(err, NotNil)

	_, err = negotiateCredSSPVersion(6, 0, 0)
	c.Assert(err, NotNil)

	// Caller requires 5+, server offers 3 -> rejected downgrade.
	_, err = negotiateCredSSPVersion(6, 3, 5)
	c.Assert(err, NotNil)

	v, err = negotiateCredSSPVersion(6, 6, 5)
	c.Assert(err, IsNil)
	c.Assert(v, Equals, 6)
}

// TestDERSequenceComplete guards the DER-length-based framing used to decide a
// full TSRequest has arrived.
func (s *WinRMSuite) TestDERSequenceComplete(c *C) {
	encoded, err := marshalTSRequest(tsRequest{
		Version:    credSSPDefaultVersion,
		NegoTokens: []negoDataItem{{NegoToken: bytes.Repeat([]byte{0x41}, 300)}},
	})
	c.Assert(err, IsNil)

	done, _, err := derSequenceComplete(encoded[:4])
	c.Assert(err, IsNil)
	c.Assert(done, Equals, false)

	done, total, err := derSequenceComplete(encoded)
	c.Assert(err, IsNil)
	c.Assert(done, Equals, true)
	c.Assert(total, Equals, len(encoded))

	// Trailing bytes beyond the SEQUENCE are not counted in its length.
	done, total, err = derSequenceComplete(append(append([]byte(nil), encoded...), 0xFF, 0xFF))
	c.Assert(err, IsNil)
	c.Assert(done, Equals, true)
	c.Assert(total, Equals, len(encoded))

	_, _, err = derSequenceComplete([]byte{0x02, 0x01, 0x05})
	c.Assert(err, NotNil)
}

// TestCredSSPTLSConfig guards the CA/ServerName handling.
func (s *WinRMSuite) TestCredSSPTLSConfig(c *C) {
	// Bad CA bytes surface an error instead of being swallowed.
	badClient := &ClientCredSSP{endpoint: &Endpoint{Host: "winhost", CACert: []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----")}}
	_, err := badClient.tlsConfig()
	c.Assert(err, NotNil)

	// Valid CA, verifying, no explicit ServerName -> defaults to the host.
	certificate, err := generateCredSSPTestCertificate()
	c.Assert(err, IsNil)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})

	verifying := &ClientCredSSP{endpoint: &Endpoint{Host: "winhost", CACert: caPEM, Insecure: false}}
	cfg, err := verifying.tlsConfig()
	c.Assert(err, IsNil)
	c.Assert(cfg.InsecureSkipVerify, Equals, false)
	c.Assert(cfg.ServerName, Equals, "winhost")
	c.Assert(cfg.RootCAs, NotNil)

	// No CA and not explicitly insecure -> nothing to verify, so skip.
	noCA := &ClientCredSSP{endpoint: &Endpoint{Host: "winhost", Insecure: false}}
	cfg, err = noCA.tlsConfig()
	c.Assert(err, IsNil)
	c.Assert(cfg.InsecureSkipVerify, Equals, true)
}

// TestCredSSPReauthRequiredOn401 guards that a 401 on an encrypted request is
// surfaced as the re-auth sentinel so Post can re-handshake.
func (s *WinRMSuite) TestCredSSPReauthRequiredOn401(c *C) {
	clientConn, _, err := newCredSSPTLSHarness()
	c.Assert(err, IsNil)

	ts, _, _, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	c.Assert(err, IsNil)
	defer ts.Close()

	encryption, err := NewEncryption("credssp")
	c.Assert(err, IsNil)
	encryption.httpClient = &http.Client{}
	encryption.tlsConn = clientConn.tlsConn
	encryption.credsspConn = clientConn.memConn
	encryption.timeout = 5 * time.Second

	_, err = encryption.PrepareEncryptedRequest(&Client{}, ts.URL, []byte("<soap/>"))
	c.Assert(errors.Is(err, errCredSSPReauthRequired), Equals, true)
}

// TestCredSSPEncryptMessagePropagatesError ensures a tunnel failure during
// message wrapping is returned instead of silently producing a malformed body.
func (s *WinRMSuite) TestCredSSPEncryptMessagePropagatesError(c *C) {
	encryption, err := NewEncryption("credssp")
	c.Assert(err, IsNil)

	// tlsConn/credsspConn are unset, so buildCredSSPMessage fails.
	_, err = encryption.encryptMessage([]byte("payload"), "host")
	c.Assert(err, NotNil)
}

// TestCredSSPMemoryConnReadDeadline ensures the read deadline is honored so a
// starved Read returns instead of blocking forever.
func TestCredSSPMemoryConnReadDeadline(t *testing.T) {
	conn := newCredSSPMemoryConn()
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 8)
	_, err := conn.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
}

// TestCredSSPDecryptTimesOutOnTruncatedResponse guards that a server response
// shorter than the declared length times out instead of hanging (the read
// deadline must actually take effect through the TLS tunnel).
func (s *WinRMSuite) TestCredSSPDecryptTimesOutOnTruncatedResponse(c *C) {
	clientConn, serverConn, err := newCredSSPTLSHarness()
	c.Assert(err, IsNil)

	encryption, err := NewEncryption("credssp")
	c.Assert(err, IsNil)
	encryption.tlsConn = clientConn.tlsConn
	encryption.credsspConn = clientConn.memConn
	encryption.timeout = 200 * time.Millisecond

	response := []byte("short")
	_, err = serverConn.tlsConn.Write(response)
	c.Assert(err, IsNil)
	sealedFirst, err := serverConn.memConn.popOutgoing(5 * time.Second)
	c.Assert(err, IsNil)
	sealed := serverConn.memConn.drainOutgoing(sealedFirst)

	cipherName := tls.CipherSuiteName(clientConn.tlsConn.ConnectionState().CipherSuite)
	trailer := encryption.getCredSSPTrailerLength(len(response), cipherName)
	payload := make([]byte, 4+len(sealed))
	binary.LittleEndian.PutUint32(payload[:4], uint32(trailer))
	copy(payload[4:], sealed)

	start := time.Now()
	// Declare more plaintext than was actually sent.
	_, err = encryption.decryptCredsspMessage(payload, "host", len(response)+64)
	c.Assert(err, NotNil)
	c.Assert(time.Since(start) < 5*time.Second, Equals, true)
}

// TestCredSSPExchangeSurfacesHTTPError guards that an error HTTP status is
// reported instead of a vague missing-token message.
func (s *WinRMSuite) TestCredSSPExchangeSurfacesHTTPError(c *C) {
	clientConn, _, err := newCredSSPTLSHarness()
	c.Assert(err, IsNil)

	ts, _, _, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	c.Assert(err, IsNil)
	defer ts.Close()

	client := &ClientCredSSP{
		httpClient: &http.Client{},
		endpoint:   &Endpoint{Timeout: 5 * time.Second},
		tlsConn:    clientConn.tlsConn,
		memConn:    clientConn.memConn,
	}

	_, err = client.sendTSRequest(ts.URL, tsRequest{
		Version:    credSSPDefaultVersion,
		NegoTokens: []negoDataItem{{NegoToken: []byte("token")}},
	})
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Contains, "HTTP 500")
}

// TestCredSSPMemoryConnCloseRace guards finding 7: Close must not race with
// concurrent pushIncoming senders (a closed incoming channel would panic).
func TestCredSSPMemoryConnCloseRace(t *testing.T) {
	for iteration := 0; iteration < 50; iteration++ {
		conn := newCredSSPMemoryConn()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if err := conn.pushIncoming([]byte("payload")); err != nil {
					return
				}
			}
		}()

		conn.Close()
		wg.Wait()
	}
}

func (s *WinRMSuite) TestFindCredSSPToken(c *C) {
	headers := http.Header{}
	headers.Add("WWW-Authenticate", "Negotiate")
	headers.Add("WWW-Authenticate", "CredSSP YWJjZA==")

	token, found, err := findCredSSPToken(headers)
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(string(token), Equals, "abcd")
}

func TestCredSSPMemoryConn(t *testing.T) {
	conn := newCredSSPMemoryConn()
	defer conn.Close()

	payload := []byte("hello")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	out, err := conn.popOutgoing(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.pushIncoming(out); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, len(payload))
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "hello" {
		t.Fatalf("unexpected payload %q", string(buffer[:n]))
	}
}

type credSSPTLSEndpoint struct {
	tlsConn *tls.Conn
	memConn *credSSPMemoryConn
}

func newCredSSPTLSHarness() (*credSSPTLSEndpoint, *credSSPTLSEndpoint, error) {
	certificate, err := generateCredSSPTestCertificate()
	if err != nil {
		return nil, nil, err
	}

	clientMem := newCredSSPMemoryConn()
	serverMem := newCredSSPMemoryConn()

	clientTLS := tls.Client(clientMem, &tls.Config{
		//nolint:gosec
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})
	serverTLS := tls.Server(serverMem, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})

	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)
	go func() { clientErr <- clientTLS.Handshake() }()
	go func() { serverErr <- serverTLS.Handshake() }()

	if err := pumpCredSSPHandshake(clientMem, serverMem, clientErr, serverErr); err != nil {
		return nil, nil, err
	}

	return &credSSPTLSEndpoint{tlsConn: clientTLS, memConn: clientMem}, &credSSPTLSEndpoint{tlsConn: serverTLS, memConn: serverMem}, nil
}

func pumpCredSSPHandshake(clientMem, serverMem *credSSPMemoryConn, clientErr, serverErr <-chan error) error {
	clientDone := false
	serverDone := false
	timeout := time.After(10 * time.Second)

	for !clientDone || !serverDone {
		select {
		case err := <-clientErr:
			if err != nil {
				return err
			}
			clientDone = true
		case err := <-serverErr:
			if err != nil {
				return err
			}
			serverDone = true
		case outgoing := <-clientMem.outgoing:
			if err := serverMem.pushIncoming(outgoing); err != nil {
				return err
			}
		case outgoing := <-serverMem.outgoing:
			if err := clientMem.pushIncoming(outgoing); err != nil {
				return err
			}
		case <-timeout:
			return errors.New("timed out waiting for TLS handshake")
		}
	}

	return nil
}

func generateCredSSPTestCertificate() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "credssp.test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}, nil
}
