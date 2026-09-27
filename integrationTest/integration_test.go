package integrationtest

// Real-Windows integration tests for go-winrm. Every subtest is opt-in: it
// skips itself if its environment variables aren't set, so `go test ./...`
// from the repo root is always safe to run without a Windows host handy.
//
// To actually run these, see integrationTest/README.md.

import (
	"testing"

	"github.com/masterzen/winrm"
)

// scenarios: every auth/encryption combination this library supports.
// buildClient loads whichever target the scenario needs (loadTarget or
// loadKerberosTarget — each skips the subtest on its own if unconfigured)
// and returns a ready-to-use client. Kept as one slice rather than a
// separate table per target group: "produce a *winrm.Client, or skip" is
// the one shape all six scenarios actually share.
var scenarios = []struct {
	name        string
	buildClient func(t *testing.T) *winrm.Client
}{
	{"NoEncryption", func(t *testing.T) *winrm.Client {
		return loadTarget(t).client(t, nil) // nil decorator == plain Basic auth
	}},
	{"NTLM", func(t *testing.T) *winrm.Client {
		return loadTarget(t).client(t, func(t *testing.T) winrm.Transporter { return &winrm.ClientNTLM{} })
	}},
	{"NTLMSealed", func(t *testing.T) *winrm.Client {
		return loadTarget(t).client(t, func(t *testing.T) winrm.Transporter {
			encryption, err := winrm.NewEncryption("ntlm")
			if err != nil {
				t.Fatalf("NewEncryption: %v", err)
			}
			return encryption
		})
	}},
	{"CredSSP", func(t *testing.T) *winrm.Client {
		return loadTarget(t).client(t, func(t *testing.T) winrm.Transporter { return &winrm.ClientCredSSP{} })
	}},
	{"Kerberos", func(t *testing.T) *winrm.Client {
		return loadKerberosTarget(t).client(t, false)
	}},
	{"KerberosEncrypted", func(t *testing.T) *winrm.Client {
		return loadKerberosTarget(t).client(t, true)
	}},
}

func TestWinRMIntegration(t *testing.T) {
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			assertRunsComputerName(t, sc.buildClient(t))
		})
	}
}
