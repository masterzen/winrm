package winrm

import (
  "bytes"
  "fmt"
)

var (
  // Git SHA Value will be set during build
  GitSHA = "N/A"
  // update this when releasing a version
  Version = "0.8.0"
)

func GetFullVersion() string {
  var versionString bytes.Buffer
  fmt.Fprintf(&versionString, "%s", Version)
  if len(GitSHA) >= 8 {
    fmt.Fprintf(&versionString, " (%s)", GitSHA[:8])
  }
  return versionString.String()
}
