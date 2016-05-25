package winrm

import (
  "bytes"
  "fmt"
)

var (
  // Git SHA Value will be set during build
  GitSHA = "N/A"
  // update this when releasing a version
  Version = "1.0.0"
)

func GetFullVersion() string {
  var versionString bytes.Buffer
  fmt.Fprintf(&versionString, "%s-%s", Version, GitSHA)
  return versionString.String()
}
