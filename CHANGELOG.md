# Changelog

## Unreleased

- Added working Kerberos message encryption for WinRM over HTTP, including
  the Windows GSS IOV wire layout (`EC=0`, `RRC=28` for AES-SHA1, and a
  separate encrypted payload buffer). The implementation was validated
  against live Windows hosts and a working GSSAPI reference client.
- Kerberos and NTLM message encryption both use
  `application/HTTP-SPNEGO-session-encrypted`. The Kerberos path intentionally
  does not use a separate `HTTP-Kerberos-session-encrypted` content type.
- Merged three external pull requests, each bringing in a distinct
  authentication/encryption transport for WinRM:
  - **#188** (Mike Christopher) — CredSSP authentication support
    (`credssp.go`, `credssp_asn1.go`), including credential delegation and a
    TLS-tunneled message-encryption path for double-hop scenarios.
  - **#191** (CalypsoSys) — Kerberos WinRM message encryption
    (`kerberos_gss.go`, `message_encryption.go`), and the
    protocol-dispatching `Encryption` type / `messageProtector` interface
    that NTLM and CredSSP encryption now both build on.
  - **#192** (Joseph Shapiro) — NTLM seal/sign support built on
    `Azure/go-ntlmssp` instead of `bodgit/ntlmssp` (`ntlm_sealing.go`),
    depending on key-exchange support Joseph upstreamed into
    `Azure/go-ntlmssp#82`.
- Following the merge, NTLM sealing was adapted from `bodgit/ntlmssp` to
  `Azure/go-ntlmssp`: a new `azureNTLMSecuritySession` type replaces
  bodgit's `SecuritySession` for both `NewEncryption("ntlm")` and CredSSP's
  pubKeyAuth handshake step; CredSSP's own message encryption was
  refactored onto the shared `messageProtector` interface; 56-bit and
  40-bit NTLMv2 key strengths were restored to match bodgit's historical
  behavior; and a sequence-validation gap in the replacement `Unwrap` was
  fixed. `bodgit` has been fully removed from `go.mod`/`go.sum`.
