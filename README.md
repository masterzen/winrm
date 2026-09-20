# WinRM for Go

_Note_: if you're looking for the `winrm` command-line tool, this has been splitted from this project and is available at [winrm-cli](https://github.com/masterzen/winrm-cli)

This is a Go library to execute remote commands on Windows machines through
the use of WinRM/WinRS.

The library supports domain users through Kerberos, including WinRM message
encryption over HTTP.

[![Build Status](https://travis-ci.org/masterzen/winrm.svg?branch=master)](https://travis-ci.org/masterzen/winrm)
[![Coverage Status](https://coveralls.io/repos/masterzen/winrm/badge.png)](https://coveralls.io/r/masterzen/winrm)

## Contact

- Bugs: https://github.com/masterzen/winrm/issues


## Getting Started
WinRM is available on Windows Server 2008 and up. This project natively supports basic authentication for local accounts, see the steps in the next section on how to prepare the remote Windows machine for this scenario. The authentication model is pluggable, see below for an example on using Negotiate/NTLM authentication (e.g. for connecting to vanilla Azure VMs) or Kerberos authentication (using domain accounts).

_Note_: This library only supports Golang 1.7+

### Preparing the remote Windows machine for Basic authentication
This project supports only basic authentication for local accounts (domain users are not supported). The remote windows system must be prepared for winrm:

_For a PowerShell script to do what is described below in one go, check [Richard Downer's blog](http://www.frontiertown.co.uk/2011/12/overthere-control-windows-from-java/)_

On the remote host, a PowerShell prompt, using the __Run as Administrator__ option and paste in the following lines:

		winrm quickconfig
		y
		winrm set winrm/config/service/Auth '@{Basic="true"}'
		winrm set winrm/config/service '@{AllowUnencrypted="true"}'
		winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'

__N.B.:__ The Windows Firewall needs to be running to run this command. See [Microsoft Knowledge Base article #2004640](http://support.microsoft.com/kb/2004640).

__N.B.:__ Do not disable Negotiate authentication as the `winrm` command itself uses this for internal authentication, and you risk getting a system where `winrm` doesn't work anymore.

__N.B.:__ The `MaxMemoryPerShellMB` option has no effects on some Windows 2008R2 systems because of a WinRM bug. Make sure to install the hotfix described [Microsoft Knowledge Base article #2842230](http://support.microsoft.com/kb/2842230) if you need to run commands that use more than 150MB of memory.

For more information on WinRM, please refer to <a href="http://msdn.microsoft.com/en-us/library/windows/desktop/aa384426(v=vs.85).aspx">the online documentation at Microsoft's DevCenter</a>.

### Preparing the remote Windows machine for kerberos authentication
This project supports domain users via kerberos authentication. The remote windows system must be prepared for winrm:

On the remote host, a PowerShell prompt, using the __Run as Administrator__ option and paste in the following lines:

                winrm quickconfig
                y
                winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'

Kerberos can protect the SOAP message body when `MessageEncryption` is enabled,
so `AllowUnencrypted=true` is not required. HTTPS remains useful because it also
protects HTTP headers and provides certificate-based server identity.

All other __N.B__ points of "Preparing the remote Windows machine for Basic authentication" also apply.


### Building the winrm go and executable

You can build winrm from source:

```sh
git clone https://github.com/masterzen/winrm
cd winrm
make
```

_Note_: this winrm code doesn't depend anymore on [Gokogiri](https://github.com/moovweb/gokogiri) which means it is now in pure Go.

_Note_: you need go 1.5+. Please check your installation with

```
go version
```

## Command-line usage

For command-line usage check the [winrm-cli project](https://github.com/masterzen/winrm-cli)

## Library Usage

**Warning the API might be subject to change.**

For the fast version (this doesn't allow to send input to the command) and it's using HTTP as the transport:

```go
package main

import (
	"github.com/masterzen/winrm"
	"os"
)

endpoint := winrm.NewEndpoint(host, 5986, false, false, nil, nil, nil, 0)
client, err := winrm.NewClient(endpoint, "Administrator", "secret")
if err != nil {
	panic(err)
}
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
client.RunWithContext(ctx, "ipconfig /all", os.Stdout, os.Stderr)
```

or
```go
package main
import (
  "github.com/masterzen/winrm"
  "fmt"
  "os"
)

endpoint := winrm.NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
client, err := winrm.NewClient(endpoint,"Administrator", "secret")
if err != nil {
	panic(err)
}

ctx, cancel := context.WithCancel(context.Background())
defer cancel()
_, err := client.RunWithContextWithInput(ctx, "ipconfig", os.Stdout, os.Stderr, os.Stdin)
if err != nil {
	panic(err)
}

```

By passing a TransportDecorator in the Parameters struct it is possible to use different Transports (e.g. NTLM)

```go
package main
import (
  "github.com/masterzen/winrm"
  "fmt"
  "os"
)

endpoint := winrm.NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)

params := DefaultParameters
params.TransportDecorator = func() Transporter { return &ClientNTLM{} }

client, err := NewClientWithParameters(endpoint, "test", "test", params)
if err != nil {
	panic(err)
}

_, err := client.RunWithInput("ipconfig", os.Stdout, os.Stderr, os.Stdin)
if err != nil {
	panic(err)
}

```

Passing a `TransportDecorator` also permits Kerberos authentication:

```go
package main

import (
	"context"
	"os"

	"github.com/masterzen/winrm"
)

func main() {
	endpoint := winrm.NewEndpoint("srv-win", 5985, false, false, nil, nil, nil, 0)

	params := *winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return &winrm.ClientKerberos{
			Username:          "test",
			Password:          "s3cr3t",
			Hostname:          "srv-win",
			Realm:             "DOMAIN.LAN",
			Port:              5985,
			Proto:             "http",
			KrbConf:           "/etc/krb5.conf",
			SPN:               "HTTP/srv-win",
			MessageEncryption: true,
		}
	}

	client, err := winrm.NewClientWithParameters(endpoint, "test", "s3cr3t", &params)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = client.RunWithContextWithInput(ctx, "ipconfig", os.Stdout, os.Stderr, os.Stdin)
	if err != nil {
		panic(err)
	}
}

```

`MessageEncryption` is opt-in to preserve compatibility with existing callers.
When enabled, the client establishes a mutually authenticated Kerberos context,
encrypts each SOAP request using the negotiated Kerberos enctype, and requires
encrypted responses. Password and credential-cache authentication are both
supported. Set `KrbCCache` instead of `Password` to use a cache.

The protocol-selected encryption constructors accept `"ntlm"` and
`"kerberos"`. For Kerberos, `NewEncryptionWithSettings` applies the same
settings shown above and delegates authentication and message protection to
`ClientKerberos`. CredSSP is intentionally not accepted until a CredSSP
authentication transport is available.

Kerberos message encryption supports AES128/AES256 SHA-1 and SHA-2 enctypes,
and legacy RC4-HMAC. AES is strongly preferred. The export-strength RC4
enctype is not supported.

The SPN should normally be `HTTP/fully-qualified-hostname`; using an IP address
usually fails because it does not identify the host's registered service
principal. A `ClientKerberos` serializes requests because GSS message sequence
numbers are stateful.

### Kerberos configuration

Kerberos requires a MIT/Heimdal-style `krb5.conf` file. The Go Kerberos
library reads this file to determine the default realm and how to locate the
realm's KDC. `ClientKerberos.KrbConf` must point to the file; the library does not
create one or discover its location automatically.

A minimal Active Directory configuration is:

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    EXAMPLE.COM = {
        kdc = dc01.example.com
        admin_server = dc01.example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

Replace the realm, domain, and domain-controller names with values from the
Active Directory environment. A domain controller provides the KDC service,
normally on TCP and UDP port 88. Instead of listing a KDC explicitly, DNS SRV
discovery can be enabled with `dns_lookup_kdc = true`, provided the client can
resolve the domain's `_kerberos._tcp` records.

Kerberos also requires synchronized clocks; a substantial time difference
between the client and KDC will cause authentication to fail. Use the server's
fully qualified hostname and its registered SPN, normally
`HTTP/server.example.com`, rather than an IP address.

### Kerberos over HTTP with message encryption

For an HTTP endpoint, enable `MessageEncryption` when constructing the
Kerberos transport. The endpoint and SPN must use the server hostname, not its
IP address:

```go
endpoint := winrm.NewEndpoint("srv-win.example.com", 5985, false, false, nil, nil, nil, 0)

params := *winrm.DefaultParameters
params.TransportDecorator = func() winrm.Transporter {
	return &winrm.ClientKerberos{
		Username:          "alice",
		Password:          "password",
		Hostname:          "srv-win.example.com",
		Realm:             "EXAMPLE.COM",
		Port:              5985,
		Proto:             "http",
		KrbConf:           "/etc/krb5.conf",
		SPN:               "HTTP/srv-win.example.com",
		MessageEncryption: true,
	}
}
```

The client first performs the normal `Negotiate` exchange. After the Kerberos
security context is established, each SOAP message is encrypted using the
negotiated GSS context. The initial `401` responses are expected; encrypted
requests do not need to repeat the `Authorization` header.

Before troubleshooting WinRM, verify that:

- the client can reach the configured KDC on TCP/UDP port 88;
- the client and domain controller clocks are synchronized;
- the configured SPN exists for the target hostname;
- the hostname resolves to the intended Windows host; and
- the account has permission to use WinRM on that host.

Message encryption is intended for HTTP. HTTPS already encrypts the transport,
although message encryption can still be requested explicitly. Kerberos and
NTLM use the WinRM SPNEGO encrypted-message content type; CredSSP is not yet
available through the Kerberos encryption constructors. AES enctypes are
preferred; RC4-HMAC is retained only for legacy interoperability.


By passing a Dial in the Parameters struct it is possible to use different dialer (e.g. tunnel through SSH)

```go
package main
     
 import (
    "github.com/masterzen/winrm"
    "golang.org/x/crypto/ssh"
    "os"
 )
 
 func main() {
 
    sshClient, err := ssh.Dial("tcp","localhost:22", &ssh.ClientConfig{
        User:"ubuntu",
        Auth: []ssh.AuthMethod{ssh.Password("ubuntu")},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    })
 
    endpoint := winrm.NewEndpoint("other-host", 5985, false, false, nil, nil, nil, 0)
 
    params := winrm.DefaultParameters
    params.Dial = sshClient.Dial
 
    client, err := winrm.NewClientWithParameters(endpoint, "test", "test", params)
    if err != nil {
        panic(err)
    }
 
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    _, err = client.RunWithContextWithInput(ctx, "ipconfig", os.Stdout, os.Stderr, os.Stdin)
    if err != nil {
        panic(err)
    }
 }

```


For a more complex example, it is possible to call the various functions directly:

```go
package main

import (
  "github.com/masterzen/winrm"
  "fmt"
  "bytes"
  "os"
)

stdin := bytes.NewBufferString("ipconfig /all")
endpoint := winrm.NewEndpoint("localhost", 5985, false, false,nil, nil, nil, 0)
client , err := winrm.NewClient(endpoint, "Administrator", "secret")
if err != nil {
	panic(err)
}
shell, err := client.CreateShell()
if err != nil {
  panic(err)
}
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
var cmd *winrm.Command
cmd, err = shell.ExecuteWithContext(ctx, "cmd.exe")
if err != nil {
  panic(err)
}

go io.Copy(cmd.Stdin, stdin)
go io.Copy(os.Stdout, cmd.Stdout)
go io.Copy(os.Stderr, cmd.Stderr)

cmd.Wait()
shell.Close()
```

For using HTTPS authentication with x 509 cert without checking the CA
```go
package main

import (
    "github.com/masterzen/winrm"
    "log"
    "os"
)

func main() {
    clientCert, err := os.ReadFile("/home/example/winrm_client_cert.pem")
    if err != nil {
        log.Fatalf("failed to read client certificate: %q", err)
    }

    clientKey, err := os.ReadFile("/home/example/winrm_client_key.pem")
    if err != nil {
        log.Fatalf("failed to read client key: %q", err)
    }

    winrm.DefaultParameters.TransportDecorator = func() winrm.Transporter {
        // winrm https module
        return &winrm.ClientAuthRequest{}
    }

    endpoint := winrm.NewEndpoint(
        "192.168.100.2", // host to connect to
        5986,            // winrm port
        true,            // use TLS
        true,            // Allow insecure connection
        nil,             // CA certificate
        clientCert,      // Client Certificate
        clientKey,       // Client Key
        0,               // Timeout
    )
    client, err := winrm.NewClient(endpoint, "Administrator", "")
    if err != nil {
        log.Fatalf("failed to create client: %q", err)
    }
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    _, err = client.RunWithContext(ctx, "whoami", os.Stdout, os.Stderr)
    if err != nil {
        log.Fatalf("failed to run command: %q", err)
    }
}
```

Note: canceling the `context.Context` passed as first argument to the various
functions of the API will not cancel the HTTP requests themselves, it will
rather cause a running command to be aborted on the remote machine via a call to
`command.Stop()`.

## Developing on WinRM

If you wish to work on `winrm` itself, you'll first need [Go](http://golang.org)
installed (version 1.5+ is _required_). Make sure you have Go properly installed,
including setting up your [GOPATH](http://golang.org/doc/code.html#GOPATH).

For some additional dependencies, Go needs [Mercurial](http://mercurial.selenic.com/)
and [Bazaar](http://bazaar.canonical.com/en/) to be installed.
Winrm itself doesn't require these, but a dependency of a dependency does.

Next, clone this repository into `$GOPATH/src/github.com/masterzen/winrm` and
then just type `make`.

You can run tests by typing `make test`.

If you make any changes to the code, run `make format` in order to automatically
format the code according to Go standards.

When new dependencies are added to winrm you can use `make updatedeps` to
get the latest and subsequently use `make` to compile.
