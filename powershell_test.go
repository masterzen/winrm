package winrm

import (
	. "gopkg.in/check.v1"
)

const (
	plainTestCmd   = "dir"
	encodedTestCmd = "JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAnAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwA7AGQAaQByAA=="
)

func (s *WinRMSuite) TestPowershell(c *C) {
	psCmd := Powershell(plainTestCmd)
	c.Assert(psCmd, Equals, "powershell.exe -EncodedCommand "+encodedTestCmd)
}

func (s *WinRMSuite) TestPowershellWithNoProfile(c *C) {
	testOpts := PowershellOptions{
		NoProfile: true,
	}
	psCmd := PowershellWithOptions(plainTestCmd, testOpts)
	c.Assert(psCmd, Equals, "powershell.exe -NoProfile -EncodedCommand "+encodedTestCmd)
}

func (s *WinRMSuite) TestPowershellWithOutputFormat(c *C) {
	testOpts := PowershellOptions{
		OutputFormat: "Text",
	}
	psCmd := PowershellWithOptions(plainTestCmd, testOpts)
	c.Assert(psCmd, Equals, "powershell.exe -OutputFormat Text -EncodedCommand "+encodedTestCmd)
}

func (s *WinRMSuite) TestPowershellWithAllOptions(c *C) {
	testOpts := PowershellOptions{
		OutputFormat: "Text",
		NoProfile:    true,
	}
	psCmd := PowershellWithOptions(plainTestCmd, testOpts)
	c.Assert(psCmd, Equals, "powershell.exe -NoProfile -OutputFormat Text -EncodedCommand "+encodedTestCmd)
}
