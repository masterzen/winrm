package winrm

import (
	"net/http"
	"testing"
)

func TestNewEncryptionProtocols(t *testing.T) {
	ntlm, err := NewEncryption("ntlm")
	if err != nil {
		t.Fatal(err)
	}
	if ntlm.protocol != "ntlm" || ntlm.kerberos != nil {
		t.Fatalf("unexpected NTLM transport: %#v", ntlm)
	}

	// Kerberos needs realm, SPN, and credentials, which the settings-less
	// NewEncryption path cannot supply. NewEncryption must reject it at
	// construction time instead of returning a client that fails later
	// with a confusing authentication error.
	if _, err := NewEncryption("kerberos"); err == nil {
		t.Fatal("expected NewEncryption(\"kerberos\") to be rejected")
	}

	configured, err := NewEncryptionWithSettings("kerberos", &Settings{
		WinRMUsername:          "user",
		WinRMPassword:          "password",
		WinRMHost:              "server.example.com",
		KrbRealm:               "EXAMPLE.COM",
		KrbConfig:              "/etc/krb5.conf",
		KrbSpn:                 "HTTP/server.example.com",
		WinRMMessageEncryption: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if configured.kerberos == nil || configured.kerberos.Username != "user" || !configured.kerberos.MessageEncryption {
		t.Fatalf("Kerberos settings were not applied: %#v", configured.kerberos)
	}

	// CredSSP has its own dedicated transport, ClientCredSSP (credssp.go),
	// which builds a credsspMessageProtector directly from the TLS tunnel
	// performCredSSPAuth establishes -- it never goes through Encryption.
	// NewEncryption/NewEncryptionWithSettings only support "ntlm" and
	// "kerberos".
	if _, err := NewEncryption("credssp"); err == nil {
		t.Fatal("expected NewEncryption(\"credssp\") to be rejected")
	}
}

// TestNTLMEncryptionUsesRawTransportForEncryptedClient guards that
// encryption.httpClient is built on a plain, unwrapped *http.Transport
// (e.raw.transport in encryption.go), not a RoundTripper middleware such as
// ntlmssp.Negotiator. The Azure-based NTLM negotiate/challenge/authenticate
// handshake and already-sealed requests are driven directly over
// encryption.httpClient via manual Authorization header handling (see
// negotiateAzureNTLMSessionKey), so a middleware-wrapped transport would
// double-negotiate or otherwise interfere.
func TestNTLMEncryptionUsesRawTransportForEncryptedClient(t *testing.T) {
	encryption, err := NewEncryption("ntlm")
	if err != nil {
		t.Fatal(err)
	}
	if err := encryption.Transport(NewEndpoint("server.example.com", 5985, false, false, nil, nil, nil, 0)); err != nil {
		t.Fatal(err)
	}

	if _, ok := encryption.httpClient.Transport.(*http.Transport); !ok {
		t.Fatalf("encrypted NTLM transport is %T, want *http.Transport", encryption.httpClient.Transport)
	}
}
