package winrm

import "fmt"

// Endpoint struct holds configurations
// for the server endpoint
type Endpoint struct {
	Host     string
	Port     int
	HTTPS    bool
	Insecure bool
	CACert   *[]byte
}

func (ep *Endpoint) url() string {
	var scheme string
	if ep.HTTPS {
		scheme = "https"
	} else {
		scheme = "http"
	}

	return fmt.Sprintf("%s://%s:%d/wsman", scheme, ep.Host, ep.Port)
}

// NewEndpoint returns new pointer to struct Endpoint
func NewEndpoint(host string, port int, https bool, insecure bool, cert *[]byte) *Endpoint {
	return &Endpoint{
		Host:     host,
		Port:     port,
		HTTPS:    https,
		Insecure: insecure,
		CACert:   cert,
	}
}
