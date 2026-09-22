package winrm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec
	"crypto/rc4" //nolint:gosec // test-double NTLM server exercises the real RC4 sealing cipher (MS-NLMP §3.4).
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:gosec,staticcheck // NTLMv2 requires MD4 (MS-NLMP §3.3.1); only used here to build a test-double NTLM server.

	"github.com/masterzen/winrm/soap"
)

// The helpers below implement just enough of a test-double NTLM server
// (MS-NLMP) to drive Encryption.Post's real NTLM negotiate/challenge/
// authenticate handshake end to end, without depending on a live Windows
// host or on bodgit's unexported SecuritySession constructor. They
// reimplement the NTLMv2 key-derivation formulas directly from MS-NLMP
// §3.3.1/§3.3.2 (the same formulas github.com/Azure/go-ntlmssp implements
// client-side), scoped to exactly what's needed to recover the exported
// session key from a real AUTHENTICATE message.

const (
	ntlmTestUsername = "testuser"
	ntlmTestPassword = "testpass"

	ntlmTestNegotiateUnicode = 0x00000001
	ntlmTestNegotiateNTLM    = 0x00000200
)

func ntlmTestToUnicode(s string) []byte {
	units := utf16.Encode([]rune(s))
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, units)
	return buf.Bytes()
}

func ntlmTestHMACMD5(key []byte, data ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, d := range data {
		mac.Write(d)
	}
	return mac.Sum(nil)
}

// ntlmTestNTOWFv2 computes the NTLMv2 password hash (MS-NLMP §3.3.2).
func ntlmTestNTOWFv2(password, username, domain string) []byte {
	h := md4.New() //nolint:gosec // NTLMv2 requires MD4 (MS-NLMP §3.3.1); only used here to build a test-double NTLM server.
	h.Write(ntlmTestToUnicode(password))
	ntHash := h.Sum(nil)
	return ntlmTestHMACMD5(ntHash, ntlmTestToUnicode(strings.ToUpper(username)+domain))
}

// ntlmTestBuildChallengeMessage builds a minimal, valid NTLM CHALLENGE_MESSAGE
// (MS-NLMP §2.2.1.2): fixed 48-byte header, no TargetName/TargetInfo payload.
func ntlmTestBuildChallengeMessage(serverChallenge [8]byte, negotiateFlags uint32) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")
	_ = binary.Write(buf, binary.LittleEndian, uint32(2)) // MessageType
	_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // TargetName.Len
	_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // TargetName.MaxLen
	_ = binary.Write(buf, binary.LittleEndian, uint32(48))
	_ = binary.Write(buf, binary.LittleEndian, negotiateFlags)
	buf.Write(serverChallenge[:])
	buf.Write(make([]byte, 8))                            // reserved
	_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // TargetInfo.Len
	_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // TargetInfo.MaxLen
	_ = binary.Write(buf, binary.LittleEndian, uint32(48))
	return buf.Bytes()
}

// ntlmTestVarField mirrors MS-NLMP's LEN_VECTOR (Len uint16, MaxLen uint16,
// Offset uint32).
type ntlmTestVarField struct {
	length uint16
	offset uint32
}

func ntlmTestReadVarField(r *bytes.Reader) (ntlmTestVarField, error) {
	var raw struct {
		Len, MaxLen uint16
		Offset      uint32
	}
	if err := binary.Read(r, binary.LittleEndian, &raw); err != nil {
		return ntlmTestVarField{}, err
	}
	return ntlmTestVarField{length: raw.Len, offset: raw.Offset}, nil
}

// ntlmTestParseAuthenticateMessage extracts NtChallengeResponse,
// EncryptedRandomSessionKey and NegotiateFlags from a raw NTLM
// AUTHENTICATE_MESSAGE (MS-NLMP §2.2.1.3).
func ntlmTestParseAuthenticateMessage(data []byte) (ntChallengeResponse, encryptedSessionKey []byte, negotiateFlags uint32, err error) {
	if len(data) < 12 || string(data[:8]) != "NTLMSSP\x00" {
		return nil, nil, 0, fmt.Errorf("bad NTLM signature")
	}
	if messageType := binary.LittleEndian.Uint32(data[8:12]); messageType != 3 {
		return nil, nil, 0, fmt.Errorf("expected AUTHENTICATE message (type 3), got type %d", messageType)
	}

	r := bytes.NewReader(data[12:])
	if _, err := ntlmTestReadVarField(r); err != nil { // LmChallengeResponse
		return nil, nil, 0, err
	}
	nt, err := ntlmTestReadVarField(r)
	if err != nil {
		return nil, nil, 0, err
	}
	for i := 0; i < 3; i++ { // DomainName, UserName, Workstation
		if _, err := ntlmTestReadVarField(r); err != nil {
			return nil, nil, 0, err
		}
	}
	sessionKeyField, err := ntlmTestReadVarField(r)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := binary.Read(r, binary.LittleEndian, &negotiateFlags); err != nil {
		return nil, nil, 0, err
	}

	slice := func(f ntlmTestVarField) ([]byte, error) {
		if f.length == 0 {
			return nil, nil
		}
		end := int(f.offset) + int(f.length)
		if f.offset > uint32(len(data)) || end > len(data) { //nolint:gosec // test NTLM messages are tiny; len(data) never approaches uint32 range.
			return nil, fmt.Errorf("field extends beyond message buffer")
		}
		return data[f.offset:end], nil
	}
	if ntChallengeResponse, err = slice(nt); err != nil {
		return nil, nil, 0, err
	}
	if encryptedSessionKey, err = slice(sessionKeyField); err != nil {
		return nil, nil, 0, err
	}
	return ntChallengeResponse, encryptedSessionKey, negotiateFlags, nil
}

// ntlmTestDeriveExportedSessionKey recovers the client's randomly generated
// ExportedSessionKey (MS-NLMP §3.4.5.1) the same way a real NTLMv2 server
// would: derive the NTLMv2 password hash from the known test credentials,
// recompute KeyExchangeKey from the NTProofStr embedded in
// NtChallengeResponse, then RC4-decrypt EncryptedRandomSessionKey with it.
func ntlmTestDeriveExportedSessionKey(t *testing.T, ntChallengeResponse, encryptedSessionKey []byte) []byte {
	t.Helper()
	if len(ntChallengeResponse) < 16 {
		t.Fatalf("NtChallengeResponse too short: %d bytes", len(ntChallengeResponse))
	}
	ntlmV2Hash := ntlmTestNTOWFv2(ntlmTestPassword, ntlmTestUsername, "")
	ntProofStr := ntChallengeResponse[:16]
	keyExchangeKey := ntlmTestHMACMD5(ntlmV2Hash, ntProofStr)

	cipher, err := rc4.NewCipher(keyExchangeKey) //nolint:gosec // test-double NTLM server exercises the real RC4 sealing cipher (MS-NLMP §3.4).
	if err != nil {
		t.Fatalf("build RC4 cipher for KeyExchangeKey: %v", err)
	}
	sessionKey := make([]byte, len(encryptedSessionKey))
	cipher.XORKeyStream(sessionKey, encryptedSessionKey)
	return sessionKey
}

// ntlmTestHandshakeServer builds an httptest.Server double that runs one side
// of the real NTLM negotiate/challenge/authenticate exchange (MS-NLMP) and
// hands the resulting server-side azureNTLMSecuritySession to onAuthenticated
// once the handshake completes. handleEncryptedRequest implements the branch
// for a request with no Authorization header -- the caller decides what
// happens once authenticated (accept and decrypt, or reject once to test
// reauth).
func ntlmTestHandshakeServer(
	t *testing.T,
	serverChallenge [8]byte,
	challengeFlags uint32,
	onAuthenticated func(session *azureNTLMSecuritySession),
	handleEncryptedRequest func(w http.ResponseWriter, r *http.Request),
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		switch {
		case auth == "":
			// Post-handshake, message-encrypted request: NTLM authentication
			// state lives on the connection, not in a per-request header.
			handleEncryptedRequest(w, r)

		case strings.HasPrefix(auth, "Negotiate "):
			token, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Negotiate "))
			if err != nil {
				t.Fatalf("decode Authorization token: %v", err)
			}
			if len(token) < 12 {
				t.Fatalf("NTLM token too short: %d bytes", len(token))
			}
			switch binary.LittleEndian.Uint32(token[8:12]) {
			case 1: // NEGOTIATE_MESSAGE
				challenge := ntlmTestBuildChallengeMessage(serverChallenge, challengeFlags)
				w.Header().Set("WWW-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(challenge))
				w.WriteHeader(http.StatusUnauthorized)
			case 3: // AUTHENTICATE_MESSAGE
				ntChallengeResponse, encryptedSessionKey, negotiatedFlags, err := ntlmTestParseAuthenticateMessage(token)
				if err != nil {
					t.Fatalf("parse AUTHENTICATE message: %v", err)
				}
				sessionKey := ntlmTestDeriveExportedSessionKey(t, ntChallengeResponse, encryptedSessionKey)
				serverSession, err := newAzureNTLMSecuritySession(sessionKey, negotiatedFlags, false, NTLMKeyExchangeOptions{})
				if err != nil {
					t.Fatalf("build server NTLM security session: %v", err)
				}
				onAuthenticated(serverSession)
				w.WriteHeader(http.StatusOK)
			default:
				t.Fatalf("unexpected NTLM message type in Authorization header")
			}

		default:
			t.Fatalf("unexpected Authorization header %q", auth)
		}
	}))
}

// ntlmTestServeEncrypted implements the ordinary (non-reauth) branch for a
// request with no Authorization header, once the handshake has completed:
// decrypt the request against wantRequest, encrypt responseBody back.
func ntlmTestServeEncrypted(t *testing.T, session *azureNTLMSecuritySession, wantRequest, responseBody string, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read encrypted request body: %v", err)
	}
	serverEncryption, err := newWinRMMessageEncryption("ntlm", azureNTLMMessageProtector{session: session})
	if err != nil {
		t.Fatalf("build server message encryption: %v", err)
	}
	decrypted, err := serverEncryption.decrypt(body)
	if err != nil {
		t.Fatalf("decrypt request body: %v", err)
	}
	if string(decrypted) != wantRequest {
		t.Fatalf("decrypted request body = %q, want %q", decrypted, wantRequest)
	}
	encryptedResponse, err := serverEncryption.encrypt([]byte(responseBody))
	if err != nil {
		t.Fatalf("encrypt response body: %v", err)
	}
	w.Header().Set("Content-Type", serverEncryption.contentType())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encryptedResponse)
}

// TestEncryptionNTLMHandshakeAndEncryptedPost drives Encryption.Post for the
// "ntlm" protocol end to end against an httptest.Server test double: a real
// NTLM negotiate/challenge/authenticate exchange (MS-NLMP), followed by a
// message-encrypted request/response (MS-WSMV §2.2.9.1). The test double
// recovers the session key from the real AUTHENTICATE message it receives
// (see ntlmTestDeriveExportedSessionKey) and uses the production
// azureNTLMSecuritySession/azureNTLMMessageProtector types to decrypt the
// request and encrypt the response, so both sides of the wire are exercised
// with real cryptography. Commit 2's temporary 128-bit-only restriction on
// newAzureNTLMSecuritySession means this only exercises the 128-bit path;
// that's the only one available until 56/40-bit support lands.
func TestEncryptionNTLMHandshakeAndEncryptedPost(t *testing.T) {
	serverChallenge := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	challengeFlags := uint32(ntlmTestNegotiateUnicode | ntlmTestNegotiateNTLM |
		ntlmNegotiateSign | ntlmNegotiateSeal |
		ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate128 | ntlmNegotiateKeyExch)

	const responseBody = "<response>ok</response>"

	requestMsg := soap.NewMessage()
	requestMsg.NewBody()
	wantRequest := requestMsg.String()

	var serverSession *azureNTLMSecuritySession

	ts := ntlmTestHandshakeServer(t, serverChallenge, challengeFlags,
		func(session *azureNTLMSecuritySession) {
			serverSession = session
		},
		func(w http.ResponseWriter, r *http.Request) {
			if serverSession == nil {
				t.Errorf("received an unauthenticated request before the NTLM handshake completed")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			wantContentType := `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`
			if ct := r.Header.Get("Content-Type"); ct != wantContentType {
				t.Errorf("unexpected request Content-Type %q, want %q", ct, wantContentType)
			}
			ntlmTestServeEncrypted(t, serverSession, wantRequest, responseBody, w, r)
		},
	)
	defer ts.Close()

	encryption, err := NewEncryption("ntlm")
	if err != nil {
		t.Fatal(err)
	}
	if err := encryption.Transport(NewEndpoint("127.0.0.1", 0, false, false, nil, nil, nil, 0)); err != nil {
		t.Fatal(err)
	}

	client := &Client{username: ntlmTestUsername, password: ntlmTestPassword, url: ts.URL}

	body, err := encryption.Post(client, requestMsg)
	if err != nil {
		t.Fatal(err)
	}
	if body != responseBody {
		t.Fatalf("response body = %q, want %q", body, responseBody)
	}
}

// TestEncryptionNTLMReauthenticatesOn401 simulates a server that has lost
// the NTLM authentication state tied to the connection (e.g. a dropped TCP
// connection or a server-side idle timeout) by answering the first
// encrypted request with a plain HTTP 401 instead of an encrypted response.
// Encryption.Post must recognize this as a reauthentication condition, run
// a fresh NTLM handshake, and retry the request -- not return the 401 error
// page as if it were the decrypted SOAP response.
func TestEncryptionNTLMReauthenticatesOn401(t *testing.T) {
	serverChallenge := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challengeFlags := uint32(ntlmTestNegotiateUnicode | ntlmTestNegotiateNTLM |
		ntlmNegotiateSign | ntlmNegotiateSeal |
		ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate128 | ntlmNegotiateKeyExch)

	const responseBody = "<response>ok</response>"

	requestMsg := soap.NewMessage()
	requestMsg.NewBody()
	wantRequest := requestMsg.String()

	var serverSession *azureNTLMSecuritySession
	handshakes := 0
	encryptedAttempts := 0

	ts := ntlmTestHandshakeServer(t, serverChallenge, challengeFlags,
		func(session *azureNTLMSecuritySession) {
			handshakes++
			serverSession = session
		},
		func(w http.ResponseWriter, r *http.Request) {
			encryptedAttempts++
			if encryptedAttempts == 1 {
				// The connection's NTLM state is gone; the server rejects the
				// encrypted request outright instead of decrypting it.
				_, _ = io.Copy(io.Discard, r.Body)
				serverSession = nil
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if serverSession == nil {
				t.Errorf("received an unauthenticated request before the retried NTLM handshake completed")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			ntlmTestServeEncrypted(t, serverSession, wantRequest, responseBody, w, r)
		},
	)
	defer ts.Close()

	encryption, err := NewEncryption("ntlm")
	if err != nil {
		t.Fatal(err)
	}
	if err := encryption.Transport(NewEndpoint("127.0.0.1", 0, false, false, nil, nil, nil, 0)); err != nil {
		t.Fatal(err)
	}

	client := &Client{username: ntlmTestUsername, password: ntlmTestPassword, url: ts.URL}

	body, err := encryption.Post(client, requestMsg)
	if err != nil {
		t.Fatal(err)
	}
	if body != responseBody {
		t.Fatalf("response body = %q, want %q", body, responseBody)
	}
	if encryptedAttempts != 2 {
		t.Fatalf("encrypted request attempts = %d, want 2 (one rejected with 401, one retried)", encryptedAttempts)
	}
	if handshakes != 2 {
		t.Fatalf("completed NTLM handshakes = %d, want 2 (initial plus the 401-triggered retry)", handshakes)
	}
}
