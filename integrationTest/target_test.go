package integrationtest

// Shared env-var-driven configuration, client construction, and the one
// assertion every scenario uses. No scenario needs anything beyond what's
// here — resist adding a JSON provider-registry file (as dnscontrol's
// integrationTest has); with a single backend (a Windows host) there's
// nothing for it to select between.

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/masterzen/winrm"
)

// target is a Windows host reachable over WinRM with a local account —
// enough for the NoEncryption, NTLM, NTLMSealed, and CredSSP scenarios.
type target struct {
	host, user, password string
	port                 int
	https, insecure      bool
}

// loadTarget reads WINRM_IT_* and skips the calling subtest if the target
// isn't configured. Every scenario that needs a plain Windows host (i.e.
// everything except Kerberos) calls this first.
func loadTarget(t *testing.T) target {
	t.Helper()
	host := os.Getenv("WINRM_IT_HOST")
	user := os.Getenv("WINRM_IT_USER")
	password := os.Getenv("WINRM_IT_PASSWORD")
	if host == "" || user == "" || password == "" {
		t.Skip("set WINRM_IT_HOST, WINRM_IT_USER, and WINRM_IT_PASSWORD to run this against a real Windows host " +
			"(see integrationTest/README.md)")
	}

	port := 5985
	if v := os.Getenv("WINRM_IT_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("invalid WINRM_IT_PORT: %v", err)
		}
		port = p
	}

	return target{
		host:     host,
		user:     user,
		password: password,
		port:     port,
		https:    os.Getenv("WINRM_IT_HTTPS") == "1",
		insecure: os.Getenv("WINRM_IT_INSECURE") != "0", // default true: lab certs are self-signed
	}
}

// client builds a *winrm.Client against tg. decorator may be nil, which
// gets plain Basic auth — confirmed against client.go's
// NewClientWithParameters: a nil TransportDecorator is exactly what
// NewClient itself leaves in place, so this one method covers all four
// non-Kerberos scenarios, "no encryption" included, with no special case.
// decorator takes t so a scenario that can fail while building its
// Transporter (NTLMSealed's NewEncryption call) fails the subtest cleanly
// instead of needing its own bespoke error plumbing.
func (tg target) client(t *testing.T, decorator func(t *testing.T) winrm.Transporter) *winrm.Client {
	t.Helper()
	endpoint := winrm.NewEndpoint(tg.host, tg.port, tg.https, tg.insecure, nil, nil, nil, 60*time.Second)
	params := *winrm.DefaultParameters
	if decorator != nil {
		params.TransportDecorator = func() winrm.Transporter { return decorator(t) }
	}
	client, err := winrm.NewClientWithParameters(endpoint, tg.user, tg.password, &params)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return client
}

// kerberosTarget is a domain-joined Windows host plus the AD account and
// krb5.conf needed to authenticate to it. Separate from target because it's
// a structurally different environment (needs a KDC), not just a different
// account on the same box.
type kerberosTarget struct {
	host, realm, user, password, ccache, krbConf string
}

// loadKerberosTarget reads WINRM_IT_KERBEROS_* and skips the calling
// subtest if the domain target isn't configured. Supply either
// WINRM_IT_KERBEROS_PASSWORD or WINRM_IT_KERBEROS_CCACHE.
func loadKerberosTarget(t *testing.T) kerberosTarget {
	t.Helper()
	host := os.Getenv("WINRM_IT_KERBEROS_HOST")
	realm := os.Getenv("WINRM_IT_KERBEROS_REALM")
	user := os.Getenv("WINRM_IT_KERBEROS_USER")
	krbConf := os.Getenv("WINRM_IT_KERBEROS_CONFIG")
	password := os.Getenv("WINRM_IT_KERBEROS_PASSWORD")
	ccache := os.Getenv("WINRM_IT_KERBEROS_CCACHE")
	if host == "" || realm == "" || user == "" || krbConf == "" || (password == "" && ccache == "") {
		t.Skip("set WINRM_IT_KERBEROS_HOST, _REALM, _USER, _CONFIG, and either _PASSWORD or _CCACHE " +
			"to run this against a real Active Directory domain (see integrationTest/README.md)")
	}
	return kerberosTarget{host: host, realm: realm, user: user, password: password, ccache: ccache, krbConf: krbConf}
}

// client builds a *winrm.Client authenticating via Kerberos, with or
// without message encryption.
func (kt kerberosTarget) client(t *testing.T, messageEncryption bool) *winrm.Client {
	t.Helper()
	params := *winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return &winrm.ClientKerberos{
			Username:          kt.user,
			Password:          kt.password,
			KrbCCache:         kt.ccache,
			Realm:             kt.realm,
			SPN:               "HTTP/" + kt.host,
			KrbConf:           kt.krbConf,
			MessageEncryption: messageEncryption,
		}
	}
	endpoint := winrm.NewEndpoint(kt.host, 5985, false, false, nil, nil, nil, 60*time.Second)
	client, err := winrm.NewClientWithParameters(endpoint, kt.user, kt.password, &params)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return client
}

// assertRunsComputerName is the one assertion every scenario ends with —
// group 1 and Kerberos alike, no separate bespoke check for either. It runs
// a trivial, verifiable command and fails with full context on any error,
// so a failure always shows what actually came back over the wire.
func assertRunsComputerName(t *testing.T, client *winrm.Client) {
	t.Helper()
	stdout, stderr, code, err := client.RunCmdWithContext(t.Context(), `powershell -NoProfile -Command "$env:COMPUTERNAME"`)
	if err != nil {
		t.Fatalf("execute remote command: %v", err)
	}
	if code != 0 {
		t.Fatalf("remote command exited %d, stderr=%q", code, stderr)
	}
	if stdout == "" {
		t.Fatal("expected non-empty COMPUTERNAME output")
	}
}
