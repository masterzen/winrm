package winrm

import (
	. "launchpad.net/gocheck"
)

func (s *WinRMSuite) TestEndpointUrl(c *C) {
	endpoint := &Endpoint{"abc", 123}
	c.Assert(endpoint.url(), Equals, "http://abc:123/wsman")
}
