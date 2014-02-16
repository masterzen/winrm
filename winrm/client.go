package winrm

import (
	"bytes"
	"github.com/masterzen/winrm/soap"
	"io"
)

type Client struct {
	Parameters
	username string
	password string
	useHTTPS bool
	http     HttpPost
}

// NewClient will create a new remote client on url, connecting with user and password
// This function doesn't connect (connection happens only when CreateShell is called)
func NewClient(hostname string, user string, password string) (client *Client) {
	params := DefaultParameters()
	params.url = winRMUrl(hostname)
	client = &Client{Parameters: *params, username: user, password: password, http: Http_post}
	return
}

// NewClient will create a new remote client on url, connecting with user and password
// This function doesn't connect (connection happens only when CreateShell is called)
func NewClientWithParameters(hostname string, user string, password string, params *Parameters) (client *Client) {
	params.url = winRMUrl(hostname)
	client = &Client{Parameters: *params, username: user, password: password, http: Http_post}
	return
}

func winRMUrl(hostname string) string {
	return "http://" + hostname + ":5985/wsman"
}

// CreateShell will create a WinRM Shell, which is the prealable for running
// commands.
func (client *Client) CreateShell() (shell *Shell, err error) {
	request := NewOpenShellRequest(client.Parameters.url, &client.Parameters)
	defer request.Free()

	response, err := client.sendRequest(request)
	if err == nil {
		var shellId string
		if shellId, err = ParseOpenShellResponse(response); err == nil {
			shell = &Shell{client: client, ShellId: shellId}
		}
	}
	return
}

func (client *Client) sendRequest(request *soap.SoapMessage) (response string, err error) {
	return client.http(client, request)
}

// Run will run command on the the remote host, writing the process stdout and stderr to
// the given writers. Note with this method it isn't possible to inject stdin.
func (client *Client) Run(command string, stdout io.Writer, stderr io.Writer) (err error) {
	shell, err := client.CreateShell()
	if err != nil {
		return err
	}
	var cmd *Command
	cmd, err = shell.Execute(command)
	if err != nil {
		return err
	}
	go io.Copy(stdout, cmd.Stdout)
	go io.Copy(stderr, cmd.Stderr)
	cmd.Wait()
	shell.Close()
	return nil
}

// Run will run command on the the remote host, returning the process stdout and stderr
// as strings, and using the input stdin string as the process input
func (client *Client) RunWithString(command string, stdin string) (stdout string, stderr string, err error) {
	shell, err := client.CreateShell()
	if err != nil {
		return "", "", err
	}
	defer shell.Close()
	var cmd *Command
	cmd, err = shell.Execute(command)
	if err != nil {
		return "", "", err
	}
	if len(stdin) > 0 {
		cmd.Stdin.Write([]byte(stdin))
	}
	var outWriter, errWriter bytes.Buffer
	go io.Copy(&outWriter, cmd.Stdout)
	go io.Copy(&errWriter, cmd.Stderr)
	cmd.Wait()
	return outWriter.String(), errWriter.String(), nil
}

// Run will run command on the the remote host, writing the process stdout and stderr to
// the given writers, and injecting the process stdin with the stdin reader.
// Warning stdin (not stdout/stderr) are bufferized, which means reading only one byte in stdin will
// send a winrm http packet to the remote host. If stdin is a pipe, it might be better for
// performance reasons to buffer it.
func (client *Client) RunWithInput(command string, stdout io.Writer, stderr io.Writer, stdin io.Reader) (err error) {
	shell, err := client.CreateShell()
	if err != nil {
		return err
	}
	defer shell.Close()
	var cmd *Command
	cmd, err = shell.Execute(command)
	if err != nil {
		return err
	}
	go io.Copy(cmd.Stdin, stdin)
	go io.Copy(stdout, cmd.Stdout)
	go io.Copy(stderr, cmd.Stderr)
	cmd.Wait()
	return nil
}
