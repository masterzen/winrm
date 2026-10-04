# NTLM/bodgit interop fixtures

This directory generates the golden vectors in
`ntlm_security_session_interop_fixtures_test.go`, at the repo root. Those
vectors prove this package stays wire-compatible with
`github.com/bodgit/ntlmssp`, the library this codebase used before it moved
to `Azure/go-ntlmssp`.

## What it generates

There are two independent sets of fixtures in that one file, both produced
by the same `generate.sh` run:

- **NTLM sealing fixtures** (6 of them): a plaintext, sealed once by the
  real, unmodified `bodgit/ntlmssp` source, together with the ciphertext
  and signature that sealing produced. `ntlm_security_session_test.go`
  decrypts each fixture with this package's own `Unwrap` and checks the
  result matches the original plaintext. One per NTLM key strength
  (128-bit, 56-bit, 40-bit), each with `NTLMSSP_NEGOTIATE_KEY_EXCH` both
  granted and not granted.
- **NtChallengeResponse fixtures** (2 of them): a hand-built
  `CHALLENGE_MESSAGE` and pinned `ClientChallenge`, together with the
  `NtChallengeResponse` bodgit's own `Client.Authenticate` derives from
  them. `ntlm_mic_interop_test.go` checks that
  `ntlmPatchChallengeForMIC` (`ntlm_mic.go`), fed into
  `ntlmssp.NewAuthenticateMessage`, derives the identical
  `NtChallengeResponse`. See
  `ntlm_security_session_interop_fixtures_test.go`'s package doc comment
  for what this mode compares (only `NtChallengeResponse`) and why it
  deliberately does not compare MIC bytes or `ExportedSessionKey`.

## Why bodgit is fetched on demand, not vendored or depended on

`bodgit/ntlmssp` is not a dependency of this module. It is not imported,
not vendored, and not listed in `go.mod` or `go.sum`. Adding it back as a
real dependency just to generate test fixtures would defeat the point of
the migration away from it.

Instead, `generate.sh` fetches bodgit's source straight from the module
proxy with `go mod download`, into a throwaway scratch directory outside
this repo. `go mod download` verifies the fetched source against
`$GOSUMDB`, so the source is authentic. The script deletes the scratch
directory when it exits.

bodgit's `SecuritySession` constructor/`Wrap` method and its
`Client.Authenticate`/`authenticateMessage.Unmarshal` are unexported, so
they cannot be called from outside the `ntlmssp` package. To call them,
the script copies a small glue file (`friend_test.go.tmpl`) into the
fetched copy of bodgit and runs it there with `go test`. That glue file
contains none of bodgit's NTLM sealing or challenge-response algorithms;
it only calls bodgit's own constructors and methods and prints the
results.

## How to run it

```
./scripts/ntlm-bodgit-fixtures/generate.sh
```

or

```
make gen-ntlm-fixtures
```

This needs network access: it fetches `bodgit/ntlmssp` from your
`$GOPROXY` and verifies it against `$GOSUMDB`. It is not part of
`make test` or `make ci`, and CI does not run it. Run it by hand, only
when the fixtures need to regenerate (for example, when
`generate.sh`'s pinned `BODGIT_VERSION` changes).

The script splices its output into
`ntlm_security_session_interop_fixtures_test.go`, at two sentinel-comment
pairs: `// ntlm-bodgit-fixtures:generated:begin`/`:end` for the sealing
fixtures, and `// ntlm-mic-bodgit-fixtures:generated:begin`/`:end` for the
NtChallengeResponse fixtures. Everything else in that file is
hand-maintained; only the blocks between the sentinels are regenerated.

## Why `friend_test.go.tmpl`, not `friend_test.go`

This directory lives inside this repo's Go module. A real `.go` file here
declaring `package ntlmssp` would make `go build ./...`, `go vet ./...`,
`go test ./...`, and `golangci-lint run ./...` at the repo root try to
compile it as a second, broken package -- it calls
`newSecuritySession`/`sourceClient`, symbols that exist only in the real
bodgit source, not anywhere in this repo. The `.tmpl` extension keeps the
Go toolchain from seeing the file at all. `generate.sh` copies it, renamed
to `friend_test.go`, into the fetched bodgit source, where those symbols
exist and it does build. The copy is deleted with the rest of the scratch
directory when the script exits.
