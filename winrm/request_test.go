package winrm

import (
	"github.com/masterzen/winrm/soap"
	"github.com/moovweb/gokogiri/xml"
	. "launchpad.net/gocheck"
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
	assertXPath(c, openShell.Doc(), "//env:Body/rsp:Shell/rsp:InputStream", "stdin")
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

func assertXPath(c *C, node *xml.XmlDocument, request string, expected string) {
	soap.NS_WIN_SHELL.RegisterNamespace(node.DocXPathCtx())
	soap.NS_ADDRESSING.RegisterNamespace(node.DocXPathCtx())
	soap.NS_WSMAN_DMTF.RegisterNamespace(node.DocXPathCtx())
	soap.NS_WSMAN_MSFT.RegisterNamespace(node.DocXPathCtx())
	soap.NS_SOAP_ENV.RegisterNamespace(node.DocXPathCtx())

	e, err := node.EvalXPath(request, nil)
	if err != nil {
		c.Fatalf("Xpath %s gives error %s", request, err)
	}
	switch e.(type) {
	default:
		c.Fatalf("Xpath %s returned unknown result %s", request, e)
	case string:
		c.Assert(e.(string), Equals, expected)
	case *xml.Node:
		c.Assert(e.(xml.Node).Content(), Equals, expected)
	case []xml.Node:
		//c.Logf("xpath returned: %s from %s into %s", e, request, node.String())
		e2 := e.([]xml.Node)
		c.Assert(e2[0].Content(), Equals, expected)
	}

}
