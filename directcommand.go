package winrm

import (
	"bytes"
	"fmt"
	"strings"
)

type DirectCommand struct {
	client *Client
	shell  *Shell
	id     string
}

func (c *DirectCommand) SendCommand(format string, arguments ...interface{}) error {
	return c.SendInput([]byte(fmt.Sprintf(format, arguments...)+"\n"), false)
}

func (c *DirectCommand) SendInput(data []byte, eof bool) error {
	request := NewSendInputRequest(c.client.url, c.shell.id, c.id, data, eof, &c.client.Parameters)
	defer request.Free()

	_, err := c.client.sendRequest(request)
	return err
}

func (c *DirectCommand) ReadOutput() ([]byte, []byte, bool, int, error) {
	request := NewGetOutputRequest(c.client.url, c.shell.id, c.id, "stdout stderr", &c.client.Parameters)
	defer request.Free()
	response, err := c.client.sendRequest(request)
	if err != nil {
		if strings.Contains(err.Error(), "OperationTimeout") {
			return nil, nil, false, 0, err
		}
		return nil, nil, true, -1, err
	}
	var exitCode int
	var stdout, stderr bytes.Buffer
	finished, exitCode, err := ParseSlurpOutputErrResponse(response, &stdout, &stderr)
	return stdout.Bytes(), stderr.Bytes(), finished, exitCode, nil
}

func (c *DirectCommand) Close() error {
	if c.shell == nil {
		return nil
	}
	defer c.shell.Close()
	if c.id != "" || c.client != nil {
		return nil
	}
	request := NewSignalRequest(c.client.url, c.shell.id, c.id, &c.client.Parameters)
	defer request.Free()

	_, err := c.client.sendRequest(request)
	return err
}

func (s *Shell) ExecuteDirect(command string, arguments ...string) (*DirectCommand, error) {
	request := NewExecuteCommandRequest(s.client.url, s.id, command, arguments, &s.client.Parameters)
	defer request.Free()

	response, err := s.client.sendRequest(request)
	if err != nil {
		return nil, err
	}

	commandID, err := ParseExecuteCommandResponse(response)
	if err != nil {
		return nil, err
	}

	return &DirectCommand{s.client, s, commandID}, nil
}
