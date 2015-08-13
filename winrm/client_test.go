package winrm

import (
	"fmt"

	"github.com/masterzen/winrm/soap"
	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestNewClient(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")

	c.Assert(err, IsNil)
	c.Assert(client.url, Equals, "http://localhost:5985/wsman")
	c.Assert(client.username, Equals, "Administrator")
	c.Assert(client.password, Equals, "v3r1S3cre7")
}

func (s *WinRMSuite) TestClientCreateShell(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		c.Assert(message.String(), Contains, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create")
		return createShellResponse, nil
	}

	shell, _ := client.CreateShell()
	c.Assert(shell.ShellId, Equals, "67A74734-DD32-4F10-89DE-49A060483810")
}

func (s *WinRMSuite) TestClientSendRequestError(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, ShellId: "67A74734-DD32-4F10-89DE-49A060483810"}
	count := 0
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		switch count {
		case 0:
			{
				count = 1
				return executeCommandResponse, nil
			}
		case 1:
			{
				count = 2
				return outputResponse, nil
			}
		default:
			{
				return doneCommandResponse, nil
			}
		}
	}
	cmd, _ := shell.Execute("ipconfig /all")

	// Test execute again after no error, shuold work
	count = 0
	command := "ipconfig /all"
	request := NewExecuteCommandRequest(shell.client.url, shell.ShellId, command, nil, &shell.client.Parameters)

	_, err = shell.client.sendRequest(request)
	c.Assert(err, IsNil)

	// If client has an error code, sendRequest should return an error
	cmd.err = fmt.Errorf("")
	cmd.exitCode = 0
	client.err = fmt.Errorf("Test /wsman: EOF")
	count = 0
	_, err = shell.client.sendRequest(request)
	c.Assert(err.Error(), NotNil)
}

func (s *WinRMSuite) TestErrorOnClient(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	// Test known errors return properly exit codes and message
	var cmd *Command
	var exitCode int

	client.err = fmt.Errorf("Test /wsman: EOF")
	// Test Message
	err = client.Error(cmd)
	c.Assert(err.Error(), Equals, "A connection terminated unexpectedly, error while sending request to endpoint: Test /wsman: EOF")
	// Test ExitCode
	exitCode = client.ExitCode(cmd)
	c.Assert(exitCode, Equals, 16000)

	client.err = fmt.Errorf("Test OperationTimeout")
	err = client.Error(cmd)
	c.Assert(err.Error(), Equals, "Operation timeout because there was no command output: Test OperationTimeout")
	exitCode = client.ExitCode(cmd)
	c.Assert(exitCode, Equals, 16001)

	// Test no message or exitcode is return if no error
	client.err = fmt.Errorf("")
	err = client.Error(cmd)
	c.Assert(err, IsNil)
	exitCode = client.ExitCode(cmd)
	c.Assert(exitCode, Equals, 0)
}

func (s *WinRMSuite) TestErrorOnCommand(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, ShellId: "67A74734-DD32-4F10-89DE-49A060483810"}
	count := 0
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		switch count {
		case 0:
			{
				count = 1
				return executeCommandResponse, nil
			}
		case 1:
			{
				count = 2
				return outputResponse, nil
			}
		default:
			{
				return doneCommandResponse, nil
			}
		}
	}

	cmd, _ := shell.Execute("ipconfig /all")

	// Test known errors return properly exit codes and message
	var exitCode int
	c.Assert(cmd, NotNil)

	cmd.err = fmt.Errorf("Command error")
	cmd.exitCode = 123

	// Test Message
	err = client.Error(cmd)
	c.Assert(err.Error(), Equals, "Command error")
	// Test ExitCode
	exitCode = client.ExitCode(cmd)
	c.Assert(exitCode, Equals, 123)

	// Test command exit code and error are returned even if the client has an error
	client.err = fmt.Errorf("Test /wsman: EOF")
	// Test Message
	err = client.Error(cmd)
	c.Assert(err.Error(), Equals, "Command error")
	// Test ExitCode
	exitCode = client.ExitCode(cmd)
	c.Assert(exitCode, Equals, 123)
}
