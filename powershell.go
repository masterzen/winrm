package winrm

import (
	"encoding/base64"
	"fmt"
	"unicode/utf16"
)

// Powershell wraps a PowerShell script
// and prepares it for execution by the winrm client
func Powershell(psCmd string) string {
	// Encode the command string as a Windows wide-character string (UTF-16LE).
	wideCmd := encodeUtf16Le(psCmd)

	// Base64 encode the command
	encodedCmd := base64.StdEncoding.EncodeToString(wideCmd)

	// Create the powershell.exe command line to execute the script
	return fmt.Sprintf("powershell.exe -EncodedCommand %s", encodedCmd)
}

func encodeUtf16Le(s string) []byte {
	d := utf16.Encode([]rune(s))
	b := make([]byte, len(d)*2)
	for i, r := range d {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return b
}
