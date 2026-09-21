package winrm

import (
	"crypto/rand"
	"crypto/rc4"

	"slices"

	. "gopkg.in/check.v1"
)

// TestNTLMSealUnsealRoundTrip checks that messages sealed with the client
// key are correctly unsealed with the matching server-derived key, and that
// the persistent cipher state (MS-NLMP CONNECTION mode) stays in sync across
// multiple messages on the same session, as ntlmSealingTransport relies on.
func (s *WinRMSuite) TestNTLMSealUnsealRoundTrip(c *C) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)

	clientCipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)
	clientSignKey := deriveClientSignKey(sessionKey)

	serverCipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)

	for seq, plaintext := range []string{"first message", "second message, same session"} {
		ciphertext, sig := sealMessage(clientCipher, clientSignKey, uint32(seq), []byte(plaintext), true)
		c.Assert(ciphertext, Not(DeepEquals), []byte(plaintext))

		decrypted, err := unsealMessage(serverCipher, clientSignKey, sig, ciphertext, true)
		c.Assert(err, IsNil)
		c.Assert(string(decrypted), Equals, plaintext)
	}
}

// TestNTLMUnsealDetectsTampering checks that a modified ciphertext or
// signature is rejected rather than silently returning corrupted plaintext.
func (s *WinRMSuite) TestNTLMUnsealDetectsTampering(c *C) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)
	signKey := deriveClientSignKey(sessionKey)

	seal := func() (ciphertext, sig []byte) {
		cipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
		c.Assert(err, IsNil)
		return sealMessage(cipher, signKey, 0, []byte("hello winrm"), true)
	}

	ciphertext, sig := seal()
	tamperedCiphertext := append([]byte(nil), ciphertext...)
	tamperedCiphertext[0] ^= 0xFF
	cipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)
	_, err = unsealMessage(cipher, signKey, sig, tamperedCiphertext, true)
	c.Assert(err, ErrorMatches, "ntlmssp: signature mismatch")

	ciphertext, sig = seal()
	tamperedSig := slices.Clone(sig)
	tamperedSig[0] ^= 0xFF
	cipher, err = rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)
	_, err = unsealMessage(cipher, signKey, tamperedSig, ciphertext, true)
	c.Assert(err, ErrorMatches, "ntlmssp: signature mismatch")
}

// TestNTLMSealUnsealRoundTripWithoutKeyExch checks that sealMessage and
// unsealMessage still interoperate when keyExch is false, as MS-NLMP
// §3.4.4.2 requires for a server that grants NTLMSSP_NEGOTIATE_SEAL without
// NTLMSSP_NEGOTIATE_KEY_EXCH: the signature checksum must round-trip
// unencrypted, not just when it's RC4-encrypted.
func (s *WinRMSuite) TestNTLMSealUnsealRoundTripWithoutKeyExch(c *C) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)

	clientCipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)
	clientSignKey := deriveClientSignKey(sessionKey)

	serverCipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)

	ciphertext, sig := sealMessage(clientCipher, clientSignKey, 0, []byte("hello winrm"), false)
	c.Assert(ciphertext, Not(DeepEquals), []byte("hello winrm"))

	decrypted, err := unsealMessage(serverCipher, clientSignKey, sig, ciphertext, false)
	c.Assert(err, IsNil)
	c.Assert(string(decrypted), Equals, "hello winrm")
}

// TestNTLMSignEncryptsChecksumOnlyWhenKeyExchGranted checks that ntlmSign's
// checksum bytes match the plain (unencrypted) HMAC-MD5 checksum when
// keyExch is false, and differ from it when keyExch is true — the concrete
// behavior MS-NLMP §3.4.4.2 requires: a server can grant
// NTLMSSP_NEGOTIATE_SEAL without granting NTLMSSP_NEGOTIATE_KEY_EXCH, and
// the checksum must stay unencrypted in that case.
func (s *WinRMSuite) TestNTLMSignEncryptsChecksumOnlyWhenKeyExchGranted(c *C) {
	sessionKey := make([]byte, 16)
	_, err := rand.Read(sessionKey)
	c.Assert(err, IsNil)
	signKey := deriveClientSignKey(sessionKey)
	seq := ntlmSeqBytes(0)
	plaintext := []byte("hello winrm")

	plainChecksum := ntlmHmacMd5(signKey, append(append([]byte(nil), seq...), plaintext...))[:8]

	noKeyExchCipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)
	sigWithoutKeyExch := ntlmSign(noKeyExchCipher, signKey, seq, plaintext, false)
	c.Assert(sigWithoutKeyExch[4:12], DeepEquals, plainChecksum)

	keyExchCipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)
	sigWithKeyExch := ntlmSign(keyExchCipher, signKey, seq, plaintext, true)
	c.Assert(sigWithKeyExch[4:12], Not(DeepEquals), plainChecksum)
}

// TestNTLMDeriveKeysAreDistinct checks that the four MS-NLMP 3.4.5 derived
// keys don't collide with each other, since sealing the wrong direction with
// the wrong key would silently produce garbage.
func (s *WinRMSuite) TestNTLMDeriveKeysAreDistinct(c *C) {
	sessionKey := []byte("0123456789abcdef")

	keys := [][]byte{
		deriveClientSignKey(sessionKey),
		deriveClientSealKey(sessionKey),
		deriveServerSignKey(sessionKey),
		deriveServerSealKey(sessionKey),
	}
	for i := range keys {
		c.Assert(keys[i], HasLen, 16)
		for j := range keys {
			if i != j {
				c.Assert(keys[i], Not(DeepEquals), keys[j])
			}
		}
	}
}
