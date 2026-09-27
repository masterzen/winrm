# integrationTest

`go test ./integrationTest/... -v` runs all six auth/encryption scenarios
go-winrm supports against real Windows hosts. Subtests skip themselves
(they never fail) when their environment variables aren't set, so it's
safe to run from CI or a laptop with no Windows host — `go test ./...`
from the repo root already covers this package and just prints skips.

## Scenarios

| Subtest name | Auth | Message encryption | Needs |
|---|---|---|---|
| `NoEncryption` | Basic | none | any Windows host, local account |
| `NTLM` | Negotiate/NTLM | none | same host |
| `NTLMSealed` | Negotiate/NTLM | `NewEncryption("ntlm")` | same host |
| `CredSSP` | CredSSP | always (TLS tunnel) | same host |
| `Kerberos` | Kerberos | none | AD domain |
| `KerberosEncrypted` | Kerberos | `ClientKerberos{MessageEncryption:true}` | AD domain |

The first four share one target (one Windows box, one local account) — no
reason to force four separate env-var groups when one account exercises all
four auth modes. Kerberos needs a second, domain-joined target with
different credentials, so it gets its own env-var group.

## Environment variables

Scenarios `NoEncryption`, `NTLM`, `NTLMSealed`, `CredSSP`:

| Variable | Required | Default | Notes |
|---|---|---|---|
| `WINRM_IT_HOST` | yes | | |
| `WINRM_IT_USER` | yes | | |
| `WINRM_IT_PASSWORD` | yes | | |
| `WINRM_IT_PORT` | no | `5985` | |
| `WINRM_IT_HTTPS` | no | off | set to `1` to enable |
| `WINRM_IT_INSECURE` | no | on | set to `0` to require a valid TLS cert; defaults to insecure since lab certs are typically self-signed |

Scenarios `Kerberos`, `KerberosEncrypted`:

| Variable | Required | Notes |
|---|---|---|
| `WINRM_IT_KERBEROS_HOST` | yes | |
| `WINRM_IT_KERBEROS_REALM` | yes | |
| `WINRM_IT_KERBEROS_USER` | yes | |
| `WINRM_IT_KERBEROS_CONFIG` | yes | path to `krb5.conf` |
| `WINRM_IT_KERBEROS_PASSWORD` | one of this or `_CCACHE` | |
| `WINRM_IT_KERBEROS_CCACHE` | one of this or `_PASSWORD` | alternative to `_PASSWORD` |

See `.env.example` for a copy-pasteable template — copy it to
`.env.integration` (gitignored), fill in real values, then:

```sh
set -a; source integrationTest/.env.integration; set +a
go test ./integrationTest/... -v
```

## Don't have a Windows box yet?

See `SETUP.md` in this directory for two concrete recipes (a free local VM
with UTM, and automated GCP provisioning) covering the four non-Kerberos
scenarios. OVHcloud and other providers, plus the fuller Active Directory
setup needed for the Kerberos scenarios, are documented separately outside
this repo — `SETUP.md` links to that for anyone who wants to go that far.

## Running a subset

```sh
go test ./integrationTest/... -run TestWinRMIntegration/NTLMSealed -v
```

Plain `-run` works fine here — there are only six scenarios, no need for
custom flags to select among them.

## Security note

Never commit `.env.integration`, since it holds a real Windows account
password. It's already covered by this repo's `.gitignore`.
