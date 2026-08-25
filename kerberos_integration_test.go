package winrm

import (
	"bytes"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestKerberosMessageEncryptionIntegration is intentionally opt-in because it
// requires an Active Directory account and a Windows host. It exercises a full
// shell lifecycle over HTTP with AllowUnencrypted disabled.
//
// Required environment variables:
//
//	WINRM_KERBEROS_INTEGRATION=1
//	WINRM_KERBEROS_HOST=server.example.com
//	WINRM_KERBEROS_REALM=EXAMPLE.COM
//	WINRM_KERBEROS_USER=user
//	WINRM_KERBEROS_CONFIG=/etc/krb5.conf
//
// Supply either WINRM_KERBEROS_PASSWORD or WINRM_KERBEROS_CCACHE.
func TestKerberosMessageEncryptionIntegration(t *testing.T) {
	if os.Getenv("WINRM_KERBEROS_INTEGRATION") != "1" {
		t.Skip("set WINRM_KERBEROS_INTEGRATION=1 to run the Active Directory integration test")
	}
	host := requiredIntegrationEnv(t, "WINRM_KERBEROS_HOST")
	realm := requiredIntegrationEnv(t, "WINRM_KERBEROS_REALM")
	username := requiredIntegrationEnv(t, "WINRM_KERBEROS_USER")
	krbConfig := requiredIntegrationEnv(t, "WINRM_KERBEROS_CONFIG")
	password := os.Getenv("WINRM_KERBEROS_PASSWORD")
	cache := os.Getenv("WINRM_KERBEROS_CCACHE")
	if password == "" && cache == "" {
		t.Fatal("set WINRM_KERBEROS_PASSWORD or WINRM_KERBEROS_CCACHE")
	}
	port := 5985
	if value := os.Getenv("WINRM_KERBEROS_PORT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("invalid WINRM_KERBEROS_PORT: %v", err)
		}
		port = parsed
	}

	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 60*time.Second)
	parameters := *DefaultParameters
	parameters.TransportDecorator = func() Transporter {
		return &ClientKerberos{
			Username:          username,
			Password:          password,
			Realm:             realm,
			SPN:               "HTTP/" + host,
			KrbConf:           krbConfig,
			KrbCCache:         cache,
			MessageEncryption: true,
		}
	}
	winRMClient, err := NewClientWithParameters(endpoint, username, password, &parameters)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exitCode, err := winRMClient.Run("echo kerberos-message-encryption", &stdout, &stderr)
	if err != nil {
		t.Fatalf("run command: %v; stderr: %s", err, stderr.String())
	}
	if exitCode != 0 || !bytes.Contains(stdout.Bytes(), []byte("kerberos-message-encryption")) {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
}

func requiredIntegrationEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
