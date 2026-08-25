# Changelog

## Unreleased

- Added working Kerberos message encryption for WinRM over HTTP, including
  the Windows GSS IOV wire layout (`EC=0`, `RRC=28` for AES-SHA1, and a
  separate encrypted payload buffer). The implementation was validated
  against live Windows hosts and a working GSSAPI reference client.
- Kerberos and NTLM message encryption both use
  `application/HTTP-SPNEGO-session-encrypted`. The Kerberos path intentionally
  does not use a separate `HTTP-Kerberos-session-encrypted` content type.
