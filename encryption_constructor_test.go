package winrm

import (
	"net/http"
	"testing"

	"github.com/bodgit/ntlmssp"
	ntlmhttp "github.com/bodgit/ntlmssp/http"
)

func TestNewEncryptionProtocols(t *testing.T) {
	ntlm, err := NewEncryption("ntlm")
	if err != nil {
		t.Fatal(err)
	}
	if ntlm.protocol != "ntlm" || ntlm.kerberos != nil {
		t.Fatalf("unexpected NTLM transport: %#v", ntlm)
	}

	kerberos, err := NewEncryption("kerberos")
	if err != nil {
		t.Fatal(err)
	}
	if kerberos.protocol != "kerberos" || kerberos.kerberos == nil {
		t.Fatalf("unexpected Kerberos transport: %#v", kerberos)
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
	if configured.kerberos.Username != "user" || !configured.kerberos.MessageEncryption {
		t.Fatalf("Kerberos settings were not applied: %#v", configured.kerberos)
	}

	// CredSSP's authentication transport (ClientCredSSP, in credssp.go) landed
	// alongside this merge: NewEncryption("credssp") is now a valid, minimal
	// Encryption value that ClientCredSSP.Post populates (tlsConn/credsspConn/
	// httpClient/timeout) and drives directly via PrepareEncryptedRequest,
	// bypassing Post/Transport above -- see the Encryption struct's doc comment.
	credssp, err := NewEncryption("credssp")
	if err != nil {
		t.Fatal(err)
	}
	if credssp.protocol != "credssp" || string(credssp.protocolString) != "application/HTTP-CredSSP-session-encrypted" {
		t.Fatalf("unexpected CredSSP transport: %#v", credssp)
	}
}

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

	ntlmClient, err := ntlmssp.NewClient(ntlmssp.SetUserInfo("user", "password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ntlmhttp.NewClient(encryption.httpClient, ntlmClient); err != nil {
		t.Fatalf("create encrypted NTLM client: %v", err)
	}
}
