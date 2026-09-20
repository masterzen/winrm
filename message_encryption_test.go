package winrm

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type testMessageProtector struct {
	wrapPrefix []byte
	unwrapErr  error
}

func (p *testMessageProtector) Wrap(message []byte) ([]byte, error) {
	return append(append([]byte(nil), p.wrapPrefix...), message...), nil
}

func (p *testMessageProtector) Unwrap(message []byte) ([]byte, error) {
	if p.unwrapErr != nil {
		return nil, p.unwrapErr
	}
	if !bytes.HasPrefix(message, p.wrapPrefix) {
		return nil, errors.New("missing test prefix")
	}
	return append([]byte(nil), message[len(p.wrapPrefix):]...), nil
}

func TestWinRMMessageEncryptionRoundTrip(t *testing.T) {
	protector := &testMessageProtector{wrapPrefix: []byte("protected:")}
	encryption, err := newWinRMMessageEncryption("kerberos", protector)
	if err != nil {
		t.Fatal(err)
	}
	if got := encryption.contentType(); got != `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"` {
		t.Fatalf("unexpected Kerberos content type %q", got)
	}

	plaintext := []byte("<s:Envelope>hello</s:Envelope>")
	encrypted, err := encryption.encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encrypted, []byte("Length=30")) {
		t.Fatalf("encrypted MIME body does not include the original length: %q", encrypted)
	}
	decrypted, err := encryption.decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestWinRMMessageEncryptionWireFormat(t *testing.T) {
	encryption, err := newWinRMMessageEncryption("ntlm", &testMessageProtector{wrapPrefix: []byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := encryption.encrypt([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := "--Encrypted Boundary\r\n" +
		"\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n" +
		"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=3\r\n" +
		"--Encrypted Boundary\r\n" +
		"\tContent-Type: application/octet-stream\r\n"
	if !bytes.HasPrefix(body, []byte(wantPrefix)) {
		t.Fatalf("unexpected MIME prefix:\n%q", body)
	}
	if !bytes.HasSuffix(body, []byte("--Encrypted Boundary--\r\n")) {
		t.Fatalf("unexpected MIME suffix: %q", body)
	}
	if got := encryption.contentType(); got != `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"` {
		t.Fatalf("unexpected content type %q", got)
	}
}

func TestWinRMMessageEncryptionRejectsMalformedBodies(t *testing.T) {
	encryption, err := newWinRMMessageEncryption("kerberos", &testMessageProtector{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "empty", body: "", want: "expected header/payload pairs"},
		{name: "odd parts", body: "--Encrypted Boundary\r\nheader", want: "expected header/payload pairs"},
		{name: "missing length", body: "--Encrypted Boundary\r\nheader--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n", want: "missing OriginalContent length"},
		{name: "bad length", body: "--Encrypted Boundary\r\nLength=nope\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n", want: "invalid OriginalContent length"},
		{name: "missing payload header", body: "--Encrypted Boundary\r\nLength=0\r\n--Encrypted Boundary\r\npayload", want: "missing the octet-stream header"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := encryption.decrypt([]byte(test.body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got error %v, want one containing %q", err, test.want)
			}
		})
	}
}

func TestWinRMMessageEncryptionPropagatesUnwrapError(t *testing.T) {
	protector := &testMessageProtector{unwrapErr: errors.New("integrity failure")}
	encryption, err := newWinRMMessageEncryption("kerberos", protector)
	if err != nil {
		t.Fatal(err)
	}
	body, err := encryption.encrypt([]byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = encryption.decrypt(body)
	if err == nil || !strings.Contains(err.Error(), "integrity failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWinRMMessageEncryptionDecryptResponseClosesBody(t *testing.T) {
	protector := &testMessageProtector{}
	encryption, err := newWinRMMessageEncryption("kerberos", protector)
	if err != nil {
		t.Fatal(err)
	}
	body, err := encryption.encrypt([]byte("response"))
	if err != nil {
		t.Fatal(err)
	}
	tracked := &trackedReadCloser{Reader: bytes.NewReader(body)}
	response := &http.Response{Body: tracked}
	decrypted, err := encryption.decryptResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "response" || !tracked.closed {
		t.Fatalf("decrypted=%q closed=%t", decrypted, tracked.closed)
	}
}

type trackedReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackedReadCloser) Close() error {
	r.closed = true
	return nil
}
