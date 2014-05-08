/*
Copyright 2013 Brice Figureau

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"github.com/masterzen/winrm/winrm"
	"os"
)

func main() {
	var hostname = flag.String("hostname", "localhost", "winrm host")
	var user = flag.String("username", "", "winrm admin username")
	var pass = flag.String("password", "", "winrm admin username")
	var port = flag.Int("port", 5985, "winrm port")

	flag.Parse()

	client := winrm.NewClient(&winrm.Endpoint{*hostname, *port}, *user, *pass)
	client.RunWithInput(flag.Arg(0), os.Stdout, os.Stderr, os.Stdin)
}
