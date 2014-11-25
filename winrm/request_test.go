package winrm

import (
	"github.com/masterzen/simplexml/dom"
	"github.com/masterzen/winrm/soap"
	"github.com/masterzen/xmlpath"
	. "gopkg.in/check.v1"
	"strings"
	"testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type WinRMSuite struct{}

var _ = Suite(&WinRMSuite{})

func (s *WinRMSuite) TestOpenShellRequest(c *C) {
	openShell := NewOpenShellRequest("http://localhost", nil)
	defer openShell.Free()

	assertXPath(c, openShell.Doc(), "//a:Action", "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create")
	assertXPath(c, openShell.Doc(), "//a:To", "http://localhost")
	assertXPath(c, openShell.Doc(), "//env:Body/rsp:Shell/rsp:InputStreams", "stdin")
	assertXPath(c, openShell.Doc(), "//env:Body/rsp:Shell/rsp:OutputStreams", "stdout stderr")
}

func (s *WinRMSuite) TestDeleteShellRequest(c *C) {
	request := NewDeleteShellRequest("http://localhost", "SHELLID", nil)
	defer request.Free()

	assertXPath(c, request.Doc(), "//a:Action", "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete")
	assertXPath(c, request.Doc(), "//a:To", "http://localhost")
	assertXPath(c, request.Doc(), "//w:Selector[@Name=\"ShellId\"]", "SHELLID")
}

func (s *WinRMSuite) TestExecuteCommandRequest(c *C) {
	request := NewExecuteCommandRequest("http://localhost", "SHELLID", "ipconfig /all", nil)
	defer request.Free()

	assertXPath(c, request.Doc(), "//a:Action", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command")
	assertXPath(c, request.Doc(), "//a:To", "http://localhost")
	assertXPath(c, request.Doc(), "//w:Selector[@Name=\"ShellId\"]", "SHELLID")
	assertXPath(c, request.Doc(), "//w:Option[@Name=\"WINRS_CONSOLEMODE_STDIN\"]", "FALSE")
	assertXPath(c, request.Doc(), "//rsp:CommandLine/rsp:Command", "\"ipconfig /all\"")
}

func (s *WinRMSuite) TestExecuteCommandRequestEscaped(c *C) {
	request := NewExecuteCommandRequest("http://localhost", "SHELLID", "&<>\"'", nil)
	defer request.Free()

	assertXPath(c, request.Doc(), "//a:Action", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command")
	assertXPath(c, request.Doc(), "//a:To", "http://localhost")
	assertXPath(c, request.Doc(), "//w:Selector[@Name=\"ShellId\"]", "SHELLID")
	assertXPath(c, request.Doc(), "//w:Option[@Name=\"WINRS_CONSOLEMODE_STDIN\"]", "FALSE")
	assertXPath(c, request.Doc(), "//rsp:CommandLine/rsp:Command", "\"&<>\"'\"")
}

func (s *WinRMSuite) TestGetOutputRequest(c *C) {
	request := NewGetOutputRequest("http://localhost", "SHELLID", "COMMANDID", "stdout stderr", nil)
	defer request.Free()

	assertXPath(c, request.Doc(), "//a:Action", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive")
	assertXPath(c, request.Doc(), "//a:To", "http://localhost")
	assertXPath(c, request.Doc(), "//w:Selector[@Name=\"ShellId\"]", "SHELLID")
	assertXPath(c, request.Doc(), "//rsp:Receive/rsp:DesiredStream[@CommandId=\"COMMANDID\"]", "stdout stderr")
}

func (s *WinRMSuite) TestSendInputRequest(c *C) {
	request := NewSendInputRequest("http://localhost", "SHELLID", "COMMANDID", []byte{31, 32}, nil)
	defer request.Free()

	assertXPath(c, request.Doc(), "//a:Action", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send")
	assertXPath(c, request.Doc(), "//a:To", "http://localhost")
	assertXPath(c, request.Doc(), "//w:Selector[@Name=\"ShellId\"]", "SHELLID")
	assertXPath(c, request.Doc(), "//rsp:Send/rsp:Stream[@CommandId=\"COMMANDID\"]", "HyA=")
}

func (s *WinRMSuite) TestSignalRequest(c *C) {
	request := NewSignalRequest("http://localhost", "SHELLID", "COMMANDID", nil)
	defer request.Free()

	assertXPath(c, request.Doc(), "//a:Action", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command")
	assertXPath(c, request.Doc(), "//a:To", "http://localhost")
	assertXPath(c, request.Doc(), "//w:Selector[@Name=\"ShellId\"]", "SHELLID")
	assertXPath(c, request.Doc(), "//rsp:Signal[@CommandId=\"COMMANDID\"]/rsp:Code", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate")
}

func assertXPath(c *C, node *dom.Document, request string, expected string) {
	content := strings.NewReader(node.String())

	path, err := xmlpath.CompileWithNamespace(request, soap.GetAllNamespaces())
	if err != nil {
		c.Fatalf("Xpath %s gives error %s", request, err)
	}
	var root *xmlpath.Node
	root, err = xmlpath.Parse(content)
	if err != nil {
		c.Fatalf("Xpath %s gives error %s", request, err)
	}

	var e string
	var ok bool
	e, ok = path.String(root)
	c.Assert(ok, Equals, true)
	c.Assert(e, Equals, expected)
}
