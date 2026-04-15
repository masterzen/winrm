package winrm

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/text/encoding/unicode"
)

// PowershellOptions are options are passed to powershell.exe when executing a command
type PowershellOptions struct {
	NoProfile    bool
	OutputFormat string
}

// Powershell wraps a PowerShell script
// and prepares it for execution by the winrm client
func Powershell(psCmd string) string {
	return PowershellWithOptions(psCmd, PowershellOptions{})
}

// PowershellWithOptions wraps a PowerShell script
// and prepares it for execution by the winrm client. Depending on the values of the
// PowershellOptions struct the rrelevant switches are set before calling powershell.exe
func PowershellWithOptions(psCmd string, psOpts PowershellOptions) string {
	// Disable unnecessary progress bars which considered as stderr.
	psCmd = "$ProgressPreference = 'SilentlyContinue';" + psCmd

	// Encode string to UTF16-LE
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	encoded, err := encoder.String(psCmd)
	if err != nil {
		return ""
	}

	// Finally make it base64 encoded which is required for powershell.
	psCmd = base64.StdEncoding.EncodeToString([]byte(encoded))

	cmds := []string{"powershell.exe"}
	if psOpts.NoProfile {
		cmds = append(cmds, "-NoProfile")
	}
	if psOpts.OutputFormat != "" {
		cmds = append(cmds, fmt.Sprintf("-OutputFormat %s", psOpts.OutputFormat))
	}
	cmds = append(cmds, fmt.Sprintf("-EncodedCommand %s", psCmd))

	return strings.Join(cmds, " ")
}
