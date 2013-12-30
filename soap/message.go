package soap

import (
	"github.com/moovweb/gokogiri/xml"
)

type SoapMessage struct {
	document *xml.XmlDocument
	envelope *xml.ElementNode
	header   *SoapHeader
	body     *xml.ElementNode
}

type MessageBuilder interface {
	SetBody(xml.Node)
	NewBody() *xml.ElementNode
	CreateElement(xml.Node, string, Namespace) *xml.ElementNode
	CreateBodyElement(string, Namespace) *xml.ElementNode
	Header() *SoapHeader
	Doc() *xml.Document
	Free()

	String() string
}

func NewMessage() (message *SoapMessage) {
	doc := xml.CreateEmptyDocument(xml.DefaultEncodingBytes, xml.DefaultEncodingBytes)
	e := doc.CreateElementNode("Envelope")
	doc.AddChild(e)
	AddUsualNamespaces(e)
	NS_SOAP_ENV.SetTo(e)

	message = &SoapMessage{document: doc, envelope: e}
	return
}

func (message *SoapMessage) NewBody() (body *xml.ElementNode) {
	body = message.document.CreateElementNode("Body")
	message.envelope.AddChild(body)
	NS_SOAP_ENV.SetTo(body)
	return
}

func (message *SoapMessage) String() string {
	return message.document.String()
}

func (message *SoapMessage) Doc() *xml.XmlDocument {
	return message.document
}

func (message *SoapMessage) Free() {
	message.document.Free()
}

func (message *SoapMessage) CreateElement(parent xml.Node, name string, ns Namespace) (element *xml.ElementNode) {
	element = message.document.CreateElementNode(name)
	parent.AddChild(element)
	ns.SetTo(element)
	return
}

func (message *SoapMessage) CreateBodyElement(name string, ns Namespace) (element *xml.ElementNode) {
	if message.body == nil {
		message.body = message.NewBody()
	}
	return message.CreateElement(message.body, name, ns)
}

func (message *SoapMessage) Header() *SoapHeader {
	if message.header == nil {
		message.header = &SoapHeader{message: message}
	}
	return message.header
}
