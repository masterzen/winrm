package winrm

import (
	"errors"

	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestError(c *C) {
	err := winrmError{
		message: "Some test error",
	}
	same := errors.New("Some test error")
	func(err, same error) {
		var wErr winrmError
		c.Assert(errors.As(err, &wErr), Equals, true)
		c.Assert(wErr.Error(), Equals, same.Error())
	}(err, same)
}
