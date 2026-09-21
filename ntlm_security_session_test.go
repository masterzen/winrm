package winrm

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	. "gopkg.in/check.v1"
)

// ntlm128BitFlags builds NegotiateFlags with ExtendedSessionSecurity and
// Negotiate128 set, as a real 128-bit-capable server would return.
func ntlm128BitFlags() uint32 {
	return ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate128 | ntlmNegotiateSign | ntlmNegotiateSeal | ntlmNegotiateKeyExch
}

func newTestSecuritySessionPair(c *C) (client, server *azureNTLMSecuritySession) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)

	flags := ntlm128BitFlags()
	client, err = newAzureNTLMSecuritySession(sessionKey, flags, true, NTLMKeyExchangeOptions{})
	c.Assert(err, IsNil)
	server, err = newAzureNTLMSecuritySession(sessionKey, flags, false, NTLMKeyExchangeOptions{})
	c.Assert(err, IsNil)
	return client, server
}

// TestAzureNTLMSecuritySessionWrapUnwrapRoundTrip checks that a message
// sealed by the client session is correctly unsealed by the mirrored server
// session (test 1).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionWrapUnwrapRoundTrip(c *C) {
	client, server := newTestSecuritySessionPair(c)

	ciphertext, signature, err := client.Wrap([]byte("hello winrm"))
	c.Assert(err, IsNil)

	plaintext, err := server.Unwrap(ciphertext, signature)
	c.Assert(err, IsNil)
	c.Assert(string(plaintext), Equals, "hello winrm")
}

// TestAzureNTLMSecuritySessionWrapSequenceNumbersIncrease checks that three
// sequential Wraps produce distinct signatures with strictly increasing
// embedded sequence numbers (test 2).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionWrapSequenceNumbersIncrease(c *C) {
	client, _ := newTestSecuritySessionPair(c)

	var signatures [][]byte
	for i := 0; i < 3; i++ {
		_, signature, err := client.Wrap([]byte("message"))
		c.Assert(err, IsNil)
		signatures = append(signatures, signature)
	}

	var lastSeq uint32
	for i, signature := range signatures {
		c.Assert(len(signature) >= 16, Equals, true)
		seq := binary.LittleEndian.Uint32(signature[12:16])
		c.Assert(seq, Equals, uint32(i))
		if i > 0 {
			c.Assert(seq > lastSeq, Equals, true)
		}
		lastSeq = seq
		for j := 0; j < i; j++ {
			c.Assert(signature, Not(DeepEquals), signatures[j])
		}
	}
}

// TestAzureNTLMSecuritySessionRejectsReplay is the core fix: Unwrap a valid
// (ciphertext, signature) pair once (succeeds), then Unwrap the identical
// pair again — the second call must error (test 3).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionRejectsReplay(c *C) {
	client, server := newTestSecuritySessionPair(c)

	ciphertext, signature, err := client.Wrap([]byte("hello winrm"))
	c.Assert(err, IsNil)

	_, err = server.Unwrap(ciphertext, signature)
	c.Assert(err, IsNil)

	_, err = server.Unwrap(ciphertext, signature)
	c.Assert(err, ErrorMatches, "ntlmssp: unexpected sequence number in signature.*")
}

// TestAzureNTLMSecuritySessionRejectsOutOfOrder checks that feeding a
// later-sequenced message before its predecessor is rejected, and that the
// correctly-ordered message still succeeds right after — rejection must not
// desync the expected-sequence-number state (test 4).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionRejectsOutOfOrder(c *C) {
	client, server := newTestSecuritySessionPair(c)

	ciphertext0, signature0, err := client.Wrap([]byte("message zero"))
	c.Assert(err, IsNil)
	ciphertext1, signature1, err := client.Wrap([]byte("message one"))
	c.Assert(err, IsNil)

	// Feed seq 1 before seq 0: must error.
	_, err = server.Unwrap(ciphertext1, signature1)
	c.Assert(err, ErrorMatches, "ntlmssp: unexpected sequence number in signature.*")

	// The correctly-ordered message (seq 0) must still succeed right after.
	plaintext0, err := server.Unwrap(ciphertext0, signature0)
	c.Assert(err, IsNil)
	c.Assert(string(plaintext0), Equals, "message zero")

	// And now seq 1, in order, must succeed too.
	plaintext1, err := server.Unwrap(ciphertext1, signature1)
	c.Assert(err, IsNil)
	c.Assert(string(plaintext1), Equals, "message one")
}

// TestAzureNTLMSecuritySessionRejectsTamperedCiphertext checks that flipping
// a bit in a valid ciphertext causes Unwrap to fail rather than return
// corrupted plaintext (test 5).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionRejectsTamperedCiphertext(c *C) {
	client, server := newTestSecuritySessionPair(c)

	ciphertext, signature, err := client.Wrap([]byte("hello winrm"))
	c.Assert(err, IsNil)

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xFF

	_, err = server.Unwrap(tampered, signature)
	c.Assert(err, ErrorMatches, "ntlmssp: signature mismatch")
}

// TestAzureNTLMSecuritySessionRejectsShortSignature checks that a signature
// shorter than 16 bytes errors cleanly instead of panicking (test 6).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionRejectsShortSignature(c *C) {
	_, server := newTestSecuritySessionPair(c)

	_, err := server.Unwrap([]byte("ciphertext"), make([]byte, 15))
	c.Assert(err, ErrorMatches, "ntlmssp: signature must be at least 16 bytes")
}

// TestAzureNTLMSecuritySessionClientServerKeysDiffer checks that
// client-to-server and server-to-client derived key material differ (test
// 7).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionClientServerKeysDiffer(c *C) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)

	flags := ntlm128BitFlags()
	client, err := newAzureNTLMSecuritySession(sessionKey, flags, true, NTLMKeyExchangeOptions{})
	c.Assert(err, IsNil)
	server, err := newAzureNTLMSecuritySession(sessionKey, flags, false, NTLMKeyExchangeOptions{})
	c.Assert(err, IsNil)

	c.Assert(client.outgoingSignKey, Not(DeepEquals), client.incomingSignKey)
	c.Assert(client.outgoingSignKey, DeepEquals, server.incomingSignKey)
	c.Assert(client.incomingSignKey, DeepEquals, server.outgoingSignKey)
}

// TestAzureNTLMSecuritySessionConcurrentWrapIsRaceFree checks that Wrap is
// safe to call from multiple goroutines at the same time, as happens once a
// command's output-poll goroutine and its stdin-write goroutine share one
// session. Every call must return without error, and the final sequence
// counter must equal the number of calls, showing the mutex serialized every
// increment (test 13).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionConcurrentWrapIsRaceFree(c *C) {
	client, _ := newTestSecuritySessionPair(c)

	const n = 100
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := client.Wrap([]byte("concurrent message"))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		c.Assert(err, IsNil)
	}
	c.Assert(client.outgoingSeqNum, Equals, uint32(n))
}

// TestAzureNTLMSecuritySessionConcurrentUnwrapIsRaceFree checks that Unwrap
// is safe to call from multiple goroutines at the same time. It replays one
// (ciphertext, signature) pair from many goroutines at once; the mutex must
// serialize access to expectedIncomingSeqNum so exactly one call sees the
// expected sequence number and succeeds, while every other call sees the
// counter already advanced and is rejected as an unexpected sequence number
// (test 14).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionConcurrentUnwrapIsRaceFree(c *C) {
	client, server := newTestSecuritySessionPair(c)

	ciphertext, signature, err := client.Wrap([]byte("hello winrm"))
	c.Assert(err, IsNil)

	const n = 50
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := server.Unwrap(ciphertext, signature)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	c.Assert(successes, Equals, 1)
}

// TestClassifyNTLMKeyStrength is a table-driven test of
// classifyNTLMKeyStrength over all four flag combinations (test 8).
func (s *WinRMSuite) TestClassifyNTLMKeyStrength(c *C) {
	tests := []struct {
		name     string
		flags    uint32
		strength ntlmKeyStrength
		wantErr  string
	}{
		{
			name:     "extended session security + 128",
			flags:    ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate128,
			strength: ntlmKey128Bit,
		},
		{
			name:     "extended session security + 56",
			flags:    ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate56,
			strength: ntlmKey56Bit,
		},
		{
			name:     "extended session security, neither 128 nor 56",
			flags:    ntlmNegotiateExtendedSessionSecurity,
			strength: ntlmKey40Bit,
		},
		{
			name:    "no extended session security",
			flags:   ntlmNegotiate128,
			wantErr: "ntlmssp: NTLM1/LM-key mode is not supported.*",
		},
	}

	for _, t := range tests {
		strength, err := classifyNTLMKeyStrength(t.flags)
		if t.wantErr != "" {
			c.Assert(err, ErrorMatches, t.wantErr, Commentf("case %q", t.name))
			continue
		}
		c.Assert(err, IsNil, Commentf("case %q", t.name))
		c.Assert(strength, Equals, t.strength, Commentf("case %q", t.name))
	}
}

// TestAzureNTLMSecuritySessionAcceptsWeakerStrengthsByDefault is the
// compatibility regression test: NTLMKeyExchangeOptions{} zero value plus
// negotiated flags granting only 56-bit (then separately 40-bit) must
// succeed both times, matching bodgit/ntlmssp's historical
// unconditional-accept default. This is the concrete "don't break existing
// NTLM users" regression test (test 9).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionAcceptsWeakerStrengthsByDefault(c *C) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)

	var flags56 uint32 = ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate56
	_, err = newAzureNTLMSecuritySession(sessionKey, flags56, true, NTLMKeyExchangeOptions{})
	c.Assert(err, IsNil)

	var flags40 uint32 = ntlmNegotiateExtendedSessionSecurity
	_, err = newAzureNTLMSecuritySession(sessionKey, flags40, true, NTLMKeyExchangeOptions{})
	c.Assert(err, IsNil)
}

// TestAzureNTLMSecuritySessionMinimumKeyBitsOptIn checks that
// NTLMKeyExchangeOptions{MinimumKeyBits: 128} rejects a 56-bit negotiation
// (opt-in strict mode), while the same flags with zero-value options succeed
// (test 10).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionMinimumKeyBitsOptIn(c *C) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)

	var flags56 uint32 = ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate56

	_, err = newAzureNTLMSecuritySession(sessionKey, flags56, true, NTLMKeyExchangeOptions{MinimumKeyBits: 128})
	c.Assert(err, ErrorMatches, "ntlmssp: negotiated 56-bit key is below the required minimum of 128 bits")

	_, err = newAzureNTLMSecuritySession(sessionKey, flags56, true, NTLMKeyExchangeOptions{})
	c.Assert(err, IsNil)
}

// TestAzureNTLMSecuritySessionWrapUnwrapAcrossKeyStrengths is a table-driven
// Wrap/Unwrap round trip across all three key strengths, confirming
// sealKeyForStrength's truncation produces mutually-decryptable client/server
// key pairs at each size — not just that keys differ, but that build/decrypt
// actually works end to end at 56-bit and 40-bit too (test 11).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionWrapUnwrapAcrossKeyStrengths(c *C) {
	tests := []struct {
		name  string
		flags uint32
	}{
		{
			name:  "128-bit",
			flags: ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate128,
		},
		{
			name:  "56-bit",
			flags: ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate56,
		},
		{
			name:  "40-bit",
			flags: ntlmNegotiateExtendedSessionSecurity,
		},
	}

	for _, t := range tests {
		sessionKey := make([]byte, 16)
		_, err := rand.Read(sessionKey)
		c.Assert(err, IsNil, Commentf("case %q", t.name))

		client, err := newAzureNTLMSecuritySession(sessionKey, t.flags, true, NTLMKeyExchangeOptions{})
		c.Assert(err, IsNil, Commentf("case %q", t.name))
		server, err := newAzureNTLMSecuritySession(sessionKey, t.flags, false, NTLMKeyExchangeOptions{})
		c.Assert(err, IsNil, Commentf("case %q", t.name))

		ciphertext, signature, err := client.Wrap([]byte("hello winrm"))
		c.Assert(err, IsNil, Commentf("case %q", t.name))

		plaintext, err := server.Unwrap(ciphertext, signature)
		c.Assert(err, IsNil, Commentf("case %q", t.name))
		c.Assert(string(plaintext), Equals, "hello winrm", Commentf("case %q", t.name))
	}
}

// TestAzureNTLMSecuritySessionRequiresExtendedSessionSecurity checks that
// negotiated flags missing ExtendedSessionSecurity error regardless of
// MinimumKeyBits (test 12).
func (s *WinRMSuite) TestAzureNTLMSecuritySessionRequiresExtendedSessionSecurity(c *C) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)

	var flags uint32 = ntlmNegotiate128 // no ntlmNegotiateExtendedSessionSecurity
	_, err = newAzureNTLMSecuritySession(sessionKey, flags, true, NTLMKeyExchangeOptions{MinimumKeyBits: 0})
	c.Assert(err, ErrorMatches, "ntlmssp: NTLM1/LM-key mode is not supported.*")

	_, err = newAzureNTLMSecuritySession(sessionKey, flags, true, NTLMKeyExchangeOptions{MinimumKeyBits: 40})
	c.Assert(err, ErrorMatches, "ntlmssp: NTLM1/LM-key mode is not supported.*")
}

// TestAzureNTLMSecuritySessionWrapUnwrapWithoutKeyExch checks that Wrap and
// Unwrap still interoperate when the server's CHALLENGE_MESSAGE grants
// NTLMSSP_NEGOTIATE_SEAL but not NTLMSSP_NEGOTIATE_KEY_EXCH. MS-NLMP
// §3.4.4.2 requires the signature checksum to stay unencrypted in that case;
// a session that unconditionally RC4-encrypts it produces a signature
// mismatch on every message with such a server.
func (s *WinRMSuite) TestAzureNTLMSecuritySessionWrapUnwrapWithoutKeyExch(c *C) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)

	var flags uint32 = ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate128 | ntlmNegotiateSign | ntlmNegotiateSeal
	client, err := newAzureNTLMSecuritySession(sessionKey, flags, true, NTLMKeyExchangeOptions{})
	c.Assert(err, IsNil)
	server, err := newAzureNTLMSecuritySession(sessionKey, flags, false, NTLMKeyExchangeOptions{})
	c.Assert(err, IsNil)
	c.Assert(client.keyExch, Equals, false)
	c.Assert(server.keyExch, Equals, false)

	ciphertext, signature, err := client.Wrap([]byte("hello winrm"))
	c.Assert(err, IsNil)

	plaintext, err := server.Unwrap(ciphertext, signature)
	c.Assert(err, IsNil)
	c.Assert(string(plaintext), Equals, "hello winrm")
}
