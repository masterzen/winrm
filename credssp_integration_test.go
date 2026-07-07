//go:build credssp_integration

package winrm

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestCredSSPIntegration(t *testing.T) {
	host := os.Getenv("WINRM_CREDSSP_HOST")
	user := os.Getenv("WINRM_CREDSSP_USER")
	password := os.Getenv("WINRM_CREDSSP_PASSWORD")
	if host == "" || user == "" || password == "" {
		t.Skip("set WINRM_CREDSSP_HOST, WINRM_CREDSSP_USER, and WINRM_CREDSSP_PASSWORD to run CredSSP integration tests")
	}

	port := 5985
	if value := os.Getenv("WINRM_CREDSSP_PORT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("invalid WINRM_CREDSSP_PORT: %v", err)
		}
		port = parsed
	}

	useHTTPS := false
	if value := os.Getenv("WINRM_CREDSSP_HTTPS"); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			t.Fatalf("invalid WINRM_CREDSSP_HTTPS: %v", err)
		}
		useHTTPS = parsed
	}

	insecure := true
	if value := os.Getenv("WINRM_CREDSSP_INSECURE"); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			t.Fatalf("invalid WINRM_CREDSSP_INSECURE: %v", err)
		}
		insecure = parsed
	}

	endpoint := NewEndpoint(host, port, useHTTPS, insecure, nil, nil, nil, 60*time.Second)
	params := DefaultParameters
	params.TransportDecorator = func() Transporter { return &ClientCredSSP{} }

	client, err := NewClientWithParameters(endpoint, user, password, params)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	stdout, stderr, code, err := client.RunCmdWithContext(context.Background(), `powershell -NoProfile -Command "$env:COMPUTERNAME"`)
	if err != nil {
		t.Fatalf("execute remote command: %v", err)
	}
	if code != 0 {
		t.Fatalf("unexpected exit code: %d, stderr=%q", code, stderr)
	}
	if stdout == "" {
		t.Fatalf("expected non-empty stdout, stderr=%q", stderr)
	}

	t.Logf("CredSSP command succeeded: %s", fmt.Sprintf("%q", stdout))
}
