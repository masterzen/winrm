package winrm

import (
	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestEndpointUrl(c *C) {
	endpoint := &Endpoint{"abc", 123}
	c.Assert(endpoint.url(), Equals, "http://abc:123/wsman")
}
