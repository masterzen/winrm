package winrm

import (
	"bytes"
	"io"
	"strings"

	"github.com/masterzen/winrm/soap"
	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestExecuteCommand(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, ShellId: "67A74734-DD32-4F10-89DE-49A060483810"}
	count := 0
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		switch count {
		case 0:
			{
				c.Assert(message.String(), Contains, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command")
				count = 1
				return executeCommandResponse, nil
			}
		case 1:
			{
				c.Assert(message.String(), Contains, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive")
				count = 2
				return outputResponse, nil
			}
		default:
			{
				return doneCommandResponse, nil
			}
		}
	}

	command, err := shell.Execute("ipconfig /all")
	c.Assert(err, IsNil)

	var stdout, stderr bytes.Buffer
	go io.Copy(&stdout, command.Stdout)
	go io.Copy(&stderr, command.Stderr)
	command.Wait()
	c.Assert(stdout.String(), Equals, "That's all folks!!!")
	c.Assert(stderr.String(), Equals, "This is stderr, I'm pretty sure!")
}

func (s *WinRMSuite) TestStdinCommand(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5985}, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, ShellId: "67A74734-DD32-4F10-89DE-49A060483810"}
	count := 0
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		if strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send") {
			c.Assert(message.String(), Contains, "c3RhbmRhcmQgaW5wdXQ=")
			return "", nil
		} else {
			if strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command") {
				return executeCommandResponse, nil
			} else if count != 1 && strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive") {
				count = 1
				return outputResponse, nil
			} else {
				return doneCommandResponse, nil
			}
		}
	}

	command, err := shell.Execute("ipconfig /all")
	c.Assert(err, IsNil)

	command.Stdin.Write([]byte("standard input"))
	// slurp output from command
	var outWriter, errWriter bytes.Buffer
	go io.Copy(&outWriter, command.Stdout)
	go io.Copy(&errWriter, command.Stderr)
	command.Wait()
}

func (s *WinRMSuite) TestExecuteCommandCertAuth(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5986, HTTPS: true, Cert: &certBytes, Key: &keyBytes}, "", "")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, ShellId: "67A74734-DD32-4F10-89DE-49A060483810"}
	count := 0
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		switch count {
		case 0:
			{
				c.Assert(message.String(), Contains, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command")
				count = 1
				return executeCommandResponse, nil
			}
		case 1:
			{
				c.Assert(message.String(), Contains, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive")
				count = 2
				return outputResponse, nil
			}
		default:
			{
				return doneCommandResponse, nil
			}
		}
	}

	command, err := shell.Execute("ipconfig /all")
	c.Assert(err, IsNil)

	var stdout, stderr bytes.Buffer
	go io.Copy(&stdout, command.Stdout)
	go io.Copy(&stderr, command.Stderr)
	command.Wait()
	c.Assert(stdout.String(), Equals, "That's all folks!!!")
	c.Assert(stderr.String(), Equals, "This is stderr, I'm pretty sure!")
}

func (s *WinRMSuite) TestStdinCommandCertAuth(c *C) {
	client, err := NewClient(&Endpoint{Host: "localhost", Port: 5986, HTTPS: true, Cert: &certBytes, Key: &keyBytes}, "", "")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, ShellId: "67A74734-DD32-4F10-89DE-49A060483810"}
	count := 0
	client.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		if strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send") {
			c.Assert(message.String(), Contains, "c3RhbmRhcmQgaW5wdXQ=")
			return "", nil
		} else {
			if strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command") {
				return executeCommandResponse, nil
			} else if count != 1 && strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive") {
				count = 1
				return outputResponse, nil
			} else {
				return doneCommandResponse, nil
			}
		}
	}

	command, err := shell.Execute("ipconfig /all")
	c.Assert(err, IsNil)

	command.Stdin.Write([]byte("standard input"))
	// slurp output from command
	var outWriter, errWriter bytes.Buffer
	go io.Copy(&outWriter, command.Stdout)
	go io.Copy(&errWriter, command.Stderr)
	command.Wait()
}
