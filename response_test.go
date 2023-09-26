package winrm

import (
	"bytes"
	"errors"

	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestOpenShellResponse(c *C) {
	response := createShellResponse
	shellID, err := ParseOpenShellResponse(response)
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert("67A74734-DD32-4F10-89DE-49A060483810", Equals, shellID)
}

func (s *WinRMSuite) TestExecuteCommandResponse(c *C) {
	response := executeCommandResponse

	commandID, err := ParseExecuteCommandResponse(response)
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert("1A6DEE6B-EC68-4DD6-87E9-030C0048ECC4", Equals, commandID)
}

func (s *WinRMSuite) TestExecuteCommandResponseError(c *C) {
	response := executeCommandResponseWithError

	commandID, err := ParseExecuteCommandResponse(response)
	if err == nil {
		c.Fatal("expected error")
	}
	c.Assert(commandID, Equals, "")

	var execCmdRespErr *ExecuteCommandError
	if !errors.As(err, &execCmdRespErr) {
		c.Fatal("expected err to be of type ExecuteCommandError")
	}
}

func (s *WinRMSuite) TestSlurpOutputResponse(c *C) {
	response := outputResponse

	var stdout, stderr bytes.Buffer
	finished, _, err := ParseSlurpOutputErrResponse(response, &stdout, &stderr)
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert(finished, Equals, false)
	c.Assert("That's all folks!!!", Equals, stdout.String())
	c.Assert("This is stderr, I'm pretty sure!", Equals, stderr.String())
}

func (s *WinRMSuite) TestSlurpOutputSingleResponse(c *C) {
	response := singleOutputResponse

	var stream bytes.Buffer
	finished, _, err := ParseSlurpOutputResponse(response, &stream, "stdout")
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert(finished, Equals, false)
	c.Assert("That's all folks!!!", Equals, stream.String())
}

func (s *WinRMSuite) TestDoneSlurpOutputResponse(c *C) {
	response := doneCommandResponse

	var stdout, stderr bytes.Buffer
	finished, code, err := ParseSlurpOutputErrResponse(response, &stdout, &stderr)
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert(finished, Equals, true)
	c.Assert(code, Equals, 123)
	c.Assert("", Equals, stdout.String())
	c.Assert("", Equals, stderr.String())
}
