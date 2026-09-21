// Package winrm — bodgit/ntlmssp interop golden vectors.
//
// These fixtures prove wire-compatibility between this package's NTLM
// sealing (`ntlm_security_session.go`, `ntlm_sealing.go`) and
// bodgit/ntlmssp's, the library this codebase used before migrating to
// Azure/go-ntlmssp.
//
// Provenance: every fixture below is sealed by the real, unmodified
// github.com/bodgit/ntlmssp source (pinned at
// v0.0.0-20240506230425-31973bb52d9b). bodgit/ntlmssp is not a dependency
// of this module -- it is never imported, vendored, or added to
// go.mod/go.sum. Instead,
// scripts/ntlm-bodgit-fixtures/generate.sh fetches bodgit's source on
// demand (go mod download, verified against GOSUMDB), copies a small glue
// file into that fetched copy, and runs it there with `go test` to call
// bodgit's own unexported SecuritySession constructor and Wrap method
// directly. See scripts/ntlm-bodgit-fixtures/README.md for how to
// regenerate this file, and scripts/ntlm-bodgit-fixtures/friend_test.go.tmpl
// for the glue code, which contains none of bodgit's sealing algorithm.
//
// The block between the "ntlm-bodgit-fixtures:generated" sentinel comments
// below comes from that script. Do not hand-edit it; regenerate it
// instead. Every other comment in this file is hand-maintained.
//
// Formula source: bodgit/ntlmssp, security.go (BSD-3-Clause, copyright
// Matt Dainty, https://github.com/bodgit/ntlmssp), extended-session-security
// branch:
//
//	func (s *SecuritySession) Wrap(b []byte) ([]byte, []byte, error) {
//		m := append(b[:0:0], b...)
//		switch {
//		case ntlmsspNegotiateSeal.IsSet(s.negotiateFlags):
//			m = encryptRC4(s.outgoingHandle, m)
//			fallthrough
//		case ntlmsspNegotiateSign.IsSet(s.negotiateFlags):
//			signature, err := calculateSignature(b, s.negotiateFlags, s.outgoingSigningKey, s.outgoingSeqNum, s.outgoingHandle)
//			...
//		}
//	}
//
// calculateSignature, extended-session-security branch (the only one
// relevant here):
//
//	version(4 bytes, 0x01000000) || checksum(8 bytes) || seqNum(4 bytes LE) = 16 bytes total
//	checksum = HMAC-MD5(signingKey, seqNum || message)[:8], RC4-encrypted iff KEY_EXCH negotiated
//
// sealKey()/signKey() truncation rule matches sealKeyForStrength in
// ntlm_sealing.go (added in the "add real 56/40-bit NTLMv2 key derivation"
// commit): 128-bit hashes the full session key; 56-bit hashes the first 7
// bytes; 40-bit hashes the first 5 bytes; signing keys never truncate.
//
// checksum's RC4 encryption is conditional on NTLMSSP_NEGOTIATE_KEY_EXCH,
// per MS-NLMP §3.4.4.2 -- both here in bodgit and in this package's own
// ntlmSign (ntlm_sealing.go). The fixtures below cover both states of that
// flag at each key strength, so the KEY_EXCH-granted and
// KEY_EXCH-not-granted cases are both checked against real bodgit output.
package winrm

import (
	. "gopkg.in/check.v1"
)

// ntlmBodgitInteropFixture is one golden vector: a fixed session key and
// plaintext sealed by the real bodgit/ntlmssp source (not a
// reimplementation -- see the package doc comment above) at one of the
// three NTLM key strengths, with NTLMSSP_NEGOTIATE_KEY_EXCH either granted
// or not granted.
type ntlmBodgitInteropFixture struct {
	name           string
	negotiateFlags uint32
	bits           int
	sessionKey     []byte
	plaintext      []byte
	ciphertext     []byte
	signature      []byte
}

// ntlmBodgitInteropFixtures holds 6 fixtures, 2 per NTLM key strength
// (128/56/40-bit): one with NTLMSSP_NEGOTIATE_KEY_EXCH granted and one
// without. All 6 are sealed from the same fixed 16-byte session key and
// plaintext, sequence number 0, by the real bodgit/ntlmssp source (see the
// package doc comment above for how). Regenerate this block with
// scripts/ntlm-bodgit-fixtures/generate.sh; do not hand-edit it.
// ntlm-bodgit-fixtures:generated:begin
var ntlmBodgitInteropFixtures = []ntlmBodgitInteropFixture{
	{
		name:           "128-bit",
		negotiateFlags: 0x60080030,
		bits:           128,
		sessionKey:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		plaintext:      []byte("The quick brown fox jumps over the lazy dog"),
		ciphertext:     []byte{0x20, 0x6a, 0xfe, 0x73, 0x00, 0x34, 0x34, 0x61, 0x7d, 0xeb, 0x75, 0x5c, 0x8f, 0x0b, 0x4e, 0xd5, 0xc6, 0xcf, 0xcc, 0x92, 0x6e, 0xc4, 0xe8, 0x5f, 0x86, 0xe7, 0x95, 0x48, 0xea, 0xa6, 0x77, 0x23, 0xee, 0x6c, 0xbd, 0x1c, 0xca, 0x60, 0xb1, 0xe6, 0x49, 0xf0, 0x56},
		signature:      []byte{0x01, 0x00, 0x00, 0x00, 0x7e, 0xc3, 0x23, 0x1b, 0x20, 0xa8, 0x70, 0x74, 0x00, 0x00, 0x00, 0x00},
	},
	{
		name:           "56-bit",
		negotiateFlags: 0xc0080030,
		bits:           56,
		sessionKey:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		plaintext:      []byte("The quick brown fox jumps over the lazy dog"),
		ciphertext:     []byte{0xcb, 0x8d, 0xa0, 0xb4, 0x25, 0x04, 0xfc, 0x59, 0x66, 0xd0, 0x2c, 0xc1, 0x05, 0xfd, 0xdd, 0x63, 0x1c, 0xe9, 0xb1, 0x0b, 0xdf, 0xb0, 0x85, 0xfe, 0xdc, 0x83, 0x7b, 0x69, 0x91, 0xe4, 0x15, 0x5c, 0x00, 0x94, 0xf4, 0x2c, 0x50, 0xa4, 0x96, 0xf3, 0x54, 0x42, 0xb8},
		signature:      []byte{0x01, 0x00, 0x00, 0x00, 0x61, 0xac, 0xdb, 0x1e, 0x3a, 0x4c, 0x96, 0x7c, 0x00, 0x00, 0x00, 0x00},
	},
	{
		name:           "40-bit",
		negotiateFlags: 0x40080030,
		bits:           40,
		sessionKey:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		plaintext:      []byte("The quick brown fox jumps over the lazy dog"),
		ciphertext:     []byte{0x3e, 0xb1, 0x5d, 0x32, 0x3e, 0x7c, 0x02, 0xea, 0xb8, 0xb8, 0x4a, 0xa6, 0x25, 0xcf, 0x8a, 0x56, 0xa9, 0xb1, 0x9b, 0xc9, 0x39, 0xc7, 0x59, 0xd0, 0xec, 0xe7, 0x87, 0x5c, 0xc0, 0x85, 0x34, 0x64, 0x66, 0x73, 0x75, 0x7b, 0x57, 0xf1, 0xb8, 0xa9, 0x86, 0x89, 0xe6},
		signature:      []byte{0x01, 0x00, 0x00, 0x00, 0x6a, 0xa9, 0xd3, 0x7c, 0x84, 0x3e, 0x66, 0x42, 0x00, 0x00, 0x00, 0x00},
	},
	{
		name:           "128-bit-no-keyexch",
		negotiateFlags: 0x20080030,
		bits:           128,
		sessionKey:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		plaintext:      []byte("The quick brown fox jumps over the lazy dog"),
		ciphertext:     []byte{0x20, 0x6a, 0xfe, 0x73, 0x00, 0x34, 0x34, 0x61, 0x7d, 0xeb, 0x75, 0x5c, 0x8f, 0x0b, 0x4e, 0xd5, 0xc6, 0xcf, 0xcc, 0x92, 0x6e, 0xc4, 0xe8, 0x5f, 0x86, 0xe7, 0x95, 0x48, 0xea, 0xa6, 0x77, 0x23, 0xee, 0x6c, 0xbd, 0x1c, 0xca, 0x60, 0xb1, 0xe6, 0x49, 0xf0, 0x56},
		signature:      []byte{0x01, 0x00, 0x00, 0x00, 0x28, 0x74, 0x17, 0x3a, 0xf2, 0x3f, 0xe8, 0x4d, 0x00, 0x00, 0x00, 0x00},
	},
	{
		name:           "56-bit-no-keyexch",
		negotiateFlags: 0x80080030,
		bits:           56,
		sessionKey:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		plaintext:      []byte("The quick brown fox jumps over the lazy dog"),
		ciphertext:     []byte{0xcb, 0x8d, 0xa0, 0xb4, 0x25, 0x04, 0xfc, 0x59, 0x66, 0xd0, 0x2c, 0xc1, 0x05, 0xfd, 0xdd, 0x63, 0x1c, 0xe9, 0xb1, 0x0b, 0xdf, 0xb0, 0x85, 0xfe, 0xdc, 0x83, 0x7b, 0x69, 0x91, 0xe4, 0x15, 0x5c, 0x00, 0x94, 0xf4, 0x2c, 0x50, 0xa4, 0x96, 0xf3, 0x54, 0x42, 0xb8},
		signature:      []byte{0x01, 0x00, 0x00, 0x00, 0x28, 0x74, 0x17, 0x3a, 0xf2, 0x3f, 0xe8, 0x4d, 0x00, 0x00, 0x00, 0x00},
	},
	{
		name:           "40-bit-no-keyexch",
		negotiateFlags: 0x00080030,
		bits:           40,
		sessionKey:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		plaintext:      []byte("The quick brown fox jumps over the lazy dog"),
		ciphertext:     []byte{0x3e, 0xb1, 0x5d, 0x32, 0x3e, 0x7c, 0x02, 0xea, 0xb8, 0xb8, 0x4a, 0xa6, 0x25, 0xcf, 0x8a, 0x56, 0xa9, 0xb1, 0x9b, 0xc9, 0x39, 0xc7, 0x59, 0xd0, 0xec, 0xe7, 0x87, 0x5c, 0xc0, 0x85, 0x34, 0x64, 0x66, 0x73, 0x75, 0x7b, 0x57, 0xf1, 0xb8, 0xa9, 0x86, 0x89, 0xe6},
		signature:      []byte{0x01, 0x00, 0x00, 0x00, 0x28, 0x74, 0x17, 0x3a, 0xf2, 0x3f, 0xe8, 0x4d, 0x00, 0x00, 0x00, 0x00},
	},
}

// ntlm-bodgit-fixtures:generated:end

// TestAzureNTLMSecuritySessionDecryptsBodgitInteropFixtures checks
// azureNTLMSecuritySession.Unwrap against the bodgit/ntlmssp golden vectors
// above, at all three NTLM key strengths (128/56/40-bit) and both
// NTLMSSP_NEGOTIATE_KEY_EXCH states. Each fixture's ciphertext/signature
// was sealed by the real, unmodified bodgit/ntlmssp source (see this
// file's package doc comment and scripts/ntlm-bodgit-fixtures/README.md
// for how); decrypting it here with this package's own Unwrap proves the
// two are wire-compatible in every combination negotiateAzureNTLMSessionKey
// can produce.
func (s *WinRMSuite) TestAzureNTLMSecuritySessionDecryptsBodgitInteropFixtures(c *C) {
	for _, f := range ntlmBodgitInteropFixtures {
		server, err := newAzureNTLMSecuritySession(f.sessionKey, f.negotiateFlags, false, NTLMKeyExchangeOptions{})
		c.Assert(err, IsNil, Commentf("fixture %q: constructing server session", f.name))

		plaintext, err := server.Unwrap(f.ciphertext, f.signature)
		c.Assert(err, IsNil, Commentf("fixture %q: Unwrap", f.name))
		c.Assert(plaintext, DeepEquals, f.plaintext, Commentf("fixture %q: decrypted plaintext mismatch", f.name))
	}
}
