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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/masterzen/winrm/winrm"
)

func main() {
	var (
		hostname string
		user     string
		pass     string
		cmd      string
		port     int
		https    bool
		insecure bool
		cacert   string
		cert     string
		key      string
	)

	flag.StringVar(&hostname, "hostname", "localhost", "winrm host")
	flag.StringVar(&user, "username", "vagrant", "winrm admin username")
	flag.StringVar(&pass, "password", "vagrant", "winrm admin password")
	flag.IntVar(&port, "port", 5985, "winrm port")
	flag.BoolVar(&https, "https", false, "use https")
	flag.BoolVar(&insecure, "insecure", false, "skip SSL validation")
	flag.StringVar(&cacert, "cacert", "", "CA certificate to use")
	flag.StringVar(&cert, "cert", "", "Cert")
	flag.StringVar(&key, "key", "", "Key")

	flag.Parse()

	var err error
	var certBytes, keyBytes []byte
	if cert != "" && key != "" {
		certBytes, err = ioutil.ReadFile(cert)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		keyBytes, err = ioutil.ReadFile(key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		certBytes = nil
		keyBytes = nil
	}

	var CAcertBytes []byte
	if cacert != "" {
		CAcertBytes, err = ioutil.ReadFile(cacert)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		CAcertBytes = nil
	}

	cmd = flag.Arg(0)
	client, err := winrm.NewClient(&winrm.Endpoint{Host: hostname, Port: port, HTTPS: https, Insecure: insecure, CACert: &CAcertBytes, Cert: &certBytes, Key: &keyBytes}, user, pass)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	exitCode, err := client.RunWithInput(cmd, os.Stdout, os.Stderr, os.Stdin)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	os.Exit(exitCode)
}
