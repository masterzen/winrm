package winrm

import (
	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestPowershell(c *C) {
	psCmd := Powershell("dir")
	c.Assert(psCmd, Equals, "powershell.exe -EncodedCommand ZABpAHIA")
}

func (s *WinRMSuite) TestPowershellUnicodeEncodingPortuguese(c *C) {
	// 'Hello World!' in Portuguese (does not require code points above 255).
	psCmd := Powershell("'Olá Mundo!'")
	c.Assert(psCmd, Equals, "powershell.exe -EncodedCommand JwBPAGwA4QAgAE0AdQBuAGQAbwAhACcA")
}

func (s *WinRMSuite) TestPowershellUnicodeEncodingJapanese(c *C) {
	// 'Hello World!' in Japanese (requires code points above 255).
	psCmd := Powershell("'こんにちは世界！'")
	c.Assert(psCmd, Equals, "powershell.exe -EncodedCommand JwBTMJMwazBhMG8wFk5MdQH/JwA=")
}
