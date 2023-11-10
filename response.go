package winrm

import (
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ChrisTrenkamp/goxpath"
	"github.com/ChrisTrenkamp/goxpath/tree"
	"github.com/ChrisTrenkamp/goxpath/tree/xmltree"
	"github.com/masterzen/winrm/soap"
)

type ExecuteCommandError struct {
	Inner error
	Body  string
}

func (e *ExecuteCommandError) Error() string {
	if e.Inner == nil {
		return "error"
	}

	return e.Inner.Error()
}

func (e *ExecuteCommandError) Is(err error) bool {
	_, ok := err.(*ExecuteCommandError)
	return ok
}

func (b *ExecuteCommandError) Unwrap() error {
	return b.Inner
}

func first(node tree.Node, xpath string) (string, error) {
	nodes, err := xPath(node, xpath)
	if err != nil {
		return "", err
	}
	if len(nodes) < 1 {
		return "", err
	}
	return nodes[0].ResValue(), nil
}

func any(node tree.Node, xpath string) (bool, error) {
	nodes, err := xPath(node, xpath)
	if err != nil {
		return false, err
	}
	if len(nodes) > 0 {
		return true, nil
	}
	return false, nil
}

func xPath(node tree.Node, xpath string) (tree.NodeSet, error) {
	xpExec := goxpath.MustParse(xpath)
	nodes, err := xpExec.ExecNode(node, soap.GetAllXPathNamespaces())
	if err != nil {
		return nil, err
	}
	return nodes, nil
}

// ParseOpenShellResponse ParseOpenShellResponse
func ParseOpenShellResponse(response string) (string, error) {
	doc, err := xmltree.ParseXML(strings.NewReader(response))
	if err != nil {
		return "", err
	}
	return first(doc, "//w:Selector[@Name='ShellId']")
}

// ParseExecuteCommandResponse ParseExecuteCommandResponse
func ParseExecuteCommandResponse(response string) (commandId string, err error) {
	defer func() {
		if err != nil {
			err = &ExecuteCommandError{Inner: err, Body: response}
		}
	}()

	doc, err := xmltree.ParseXML(strings.NewReader(response))
	if err != nil {
		return "", fmt.Errorf("parsing xml response: %w", err)
	}

	action, err := first(doc, "//a:Action")
	if err != nil {
		return "", fmt.Errorf("getting response action: %w", err)
	}

	switch action {
	case "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse":
		commandId, err = first(doc, "//rsp:CommandId")
		if err != nil {
			return "", fmt.Errorf("finding command id: %w", err)
		}

		return commandId, nil

	default:
		return "", fmt.Errorf("unsupported action: %v", action)
	}
}

// ParseSlurpOutputErrResponse ParseSlurpOutputErrResponse
func ParseSlurpOutputErrResponse(response string, stdout, stderr io.Writer) (bool, int, error) {
	var (
		finished bool
		exitCode int
	)

	doc, err := xmltree.ParseXML(strings.NewReader(response))

	stdouts, _ := xPath(doc, "//rsp:Stream[@Name='stdout']")
	for _, node := range stdouts {
		content, _ := base64.StdEncoding.DecodeString(node.ResValue())
		stdout.Write(content)
	}
	stderrs, _ := xPath(doc, "//rsp:Stream[@Name='stderr']")
	for _, node := range stderrs {
		content, _ := base64.StdEncoding.DecodeString(node.ResValue())
		stderr.Write(content)
	}

	ended, _ := any(doc, "//*[@State='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done']")

	if ended {
		finished = ended
		if exitBool, _ := any(doc, "//rsp:ExitCode"); exitBool {
			exit, _ := first(doc, "//rsp:ExitCode")
			exitCode, _ = strconv.Atoi(exit)
		}
	} else {
		finished = false
	}

	return finished, exitCode, err
}

// ParseSlurpOutputResponse ParseSlurpOutputResponse
func ParseSlurpOutputResponse(response string, stream io.Writer, streamType string) (bool, int, error) {
	var (
		finished bool
		exitCode int
	)

	doc, err := xmltree.ParseXML(strings.NewReader(response))

	nodes, _ := xPath(doc, fmt.Sprintf("//rsp:Stream[@Name='%s']", streamType))
	for _, node := range nodes {
		content, _ := base64.StdEncoding.DecodeString(node.ResValue())
		_, _ = stream.Write(content)
	}

	ended, _ := any(doc, "//*[@State='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done']")

	if ended {
		finished = ended
		if exitBool, _ := any(doc, "//rsp:ExitCode"); exitBool {
			exit, _ := first(doc, "//rsp:ExitCode")
			exitCode, _ = strconv.Atoi(exit)
		}
	} else {
		finished = false
	}

	return finished, exitCode, err
}
