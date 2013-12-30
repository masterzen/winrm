package winrm

import (
	"encoding/base64"
	"errors"
	"github.com/masterzen/winrm/soap"
	"github.com/moovweb/gokogiri/xml"
	"io"
	"strconv"
)

func first(node *xml.XmlDocument, xpath string) (content string, err error) {
	soap.NS_WIN_SHELL.RegisterNamespace(node.DocXPathCtx())
	soap.NS_ADDRESSING.RegisterNamespace(node.DocXPathCtx())
	soap.NS_WSMAN_DMTF.RegisterNamespace(node.DocXPathCtx())
	soap.NS_WSMAN_MSFT.RegisterNamespace(node.DocXPathCtx())
	soap.NS_SOAP_ENV.RegisterNamespace(node.DocXPathCtx())

	e, err := node.EvalXPath(xpath, nil)
	if err == nil {
		switch e.(type) {
		default:
			err = errors.New("Xpath %s returned unknown result %s")
		case string:
			content = e.(string)
		case *xml.Node:
			content = e.(xml.Node).Content()
		case []xml.Node:
			e2 := e.([]xml.Node)
			content = e2[0].Content()
		}
	}
	return
}

func any(node *xml.XmlDocument, xpath string) (found bool, err error) {
	soap.NS_WIN_SHELL.RegisterNamespace(node.DocXPathCtx())
	soap.NS_ADDRESSING.RegisterNamespace(node.DocXPathCtx())
	soap.NS_WSMAN_DMTF.RegisterNamespace(node.DocXPathCtx())
	soap.NS_WSMAN_MSFT.RegisterNamespace(node.DocXPathCtx())
	soap.NS_SOAP_ENV.RegisterNamespace(node.DocXPathCtx())

	e, err := node.EvalXPath(xpath, nil)
	if err == nil && e != nil && len(e.([]xml.Node)) > 0 {
		found = true
	} else {
		found = false
	}
	return
}

func xpath(node *xml.XmlDocument, xpath string) (nodes []xml.Node, err error) {
	soap.NS_WIN_SHELL.RegisterNamespace(node.DocXPathCtx())
	soap.NS_ADDRESSING.RegisterNamespace(node.DocXPathCtx())
	soap.NS_WSMAN_DMTF.RegisterNamespace(node.DocXPathCtx())
	soap.NS_WSMAN_MSFT.RegisterNamespace(node.DocXPathCtx())
	soap.NS_SOAP_ENV.RegisterNamespace(node.DocXPathCtx())

	e, err := node.EvalXPath(xpath, nil)
	if err == nil {
		switch e.(type) {
		default:
			err = errors.New("Xpath %s returned unknown result %s")
		case []xml.Node:
			e2 := e.([]xml.Node)
			nodes = e2
		}
	}
	return
}

func ParseOpenShellResponse(response string) (shellId string, err error) {
	doc, err := xml.Parse([]byte(response), xml.DefaultEncodingBytes, nil, xml.DefaultParseOption, xml.DefaultEncodingBytes)
	defer doc.Free()

	shellId, err = first(doc, "//*[@Name='ShellId']")
	return
}

func ParseExecuteCommandResponse(response string) (commandId string, err error) {
	doc, err := xml.Parse([]byte(response), xml.DefaultEncodingBytes, nil, xml.DefaultParseOption, xml.DefaultEncodingBytes)
	defer doc.Free()

	commandId, err = first(doc, "//rsp:CommandId")
	return
}

func ParseSlurpOutputErrResponse(response string, stdout io.Writer, stderr io.Writer) (finished bool, exitCode int, err error) {
	doc, err := xml.Parse([]byte(response), xml.DefaultEncodingBytes, nil, xml.DefaultParseOption, xml.DefaultEncodingBytes)
	defer doc.Free()

	nodes, _ := xpath(doc, "//rsp:Stream")
	for _, node := range nodes {
		stream := node.Attr("Name")
		content, _ := base64.StdEncoding.DecodeString(node.Content())

		if stream == "stdout" {
			stdout.Write(content)
		} else {
			stderr.Write(content)
		}
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

	return
}

func ParseSlurpOutputResponse(response string, stream io.Writer, streamType string) (finished bool, exitCode int, err error) {
	doc, err := xml.Parse([]byte(response), xml.DefaultEncodingBytes, nil, xml.DefaultParseOption, xml.DefaultEncodingBytes)
	defer doc.Free()

	nodes, _ := xpath(doc, "//rsp:Stream")
	for _, node := range nodes {
		streamElement := node.Attr("Name")
		content, _ := base64.StdEncoding.DecodeString(node.Content())
		//		log.Println("<" + streamElement + "/" + streamType + "> -> " + string(content))
		if streamElement == streamType {
			stream.Write(content)
		}
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

	return
}
