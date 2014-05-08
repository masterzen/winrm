package winrm

import "fmt"

type Endpoint struct {
	Host string
	Port int
}

func (ep *Endpoint) url() string {
	return fmt.Sprintf("http://%s:%d/wsman", ep.Host, ep.Port)
}
