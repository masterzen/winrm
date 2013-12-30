package soap

import (
	"github.com/moovweb/gokogiri/xml"
	"github.com/moovweb/gokogiri/xpath"
)

type Namespace struct {
	prefix string
	uri    string
}

var (
	NS_SOAP_ENV    = Namespace{"env", "http://www.w3.org/2003/05/soap-envelope"}
	NS_ADDRESSING  = Namespace{"a", "http://schemas.xmlsoap.org/ws/2004/08/addressing"}
	NS_CIMBINDING  = Namespace{"b", "http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd"}
	NS_ENUM        = Namespace{"n", "http://schemas.xmlsoap.org/ws/2004/09/enumeration"}
	NS_TRANSFER    = Namespace{"x", "http://schemas.xmlsoap.org/ws/2004/09/transfer"}
	NS_WSMAN_DMTF  = Namespace{"w", "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"}
	NS_WSMAN_MSFT  = Namespace{"p", "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"}
	NS_SCHEMA_INST = Namespace{"xsi", "http://www.w3.org/2001/XMLSchema-instance"}
	NS_WIN_SHELL   = Namespace{"rsp", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"}
	NS_WSMAN_FAULT = Namespace{"f", "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"}
)

var MostUsed = [...]Namespace{NS_SOAP_ENV, NS_ADDRESSING, NS_WIN_SHELL, NS_WSMAN_DMTF, NS_WSMAN_MSFT}

func AddUsualNamespaces(node xml.Node) {
	for _, ns := range MostUsed {
		node.DeclareNamespace(ns.prefix, ns.uri)
	}
}

func (ns *Namespace) SetTo(node xml.Node) {
	node.SetNamespace(ns.prefix, ns.uri)
}

func (ns *Namespace) RegisterNamespace(xpath *xpath.XPath) {
	xpath.RegisterNamespace(ns.prefix, ns.uri)
}
