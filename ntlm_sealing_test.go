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
		ciphertext, sig := sealMessage(clientCipher, clientSignKey, uint32(seq), []byte(plaintext))
		c.Assert(ciphertext, Not(DeepEquals), []byte(plaintext))

		decrypted, err := unsealMessage(serverCipher, clientSignKey, sig, ciphertext)
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
		return sealMessage(cipher, signKey, 0, []byte("hello winrm"))
	}

	ciphertext, sig := seal()
	tamperedCiphertext := append([]byte(nil), ciphertext...)
	tamperedCiphertext[0] ^= 0xFF
	cipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)
	_, err = unsealMessage(cipher, signKey, sig, tamperedCiphertext)
	c.Assert(err, ErrorMatches, "ntlmssp: signature mismatch")

	ciphertext, sig = seal()
	tamperedSig := slices.Clone(sig)
	tamperedSig[0] ^= 0xFF
	cipher, err = rc4.NewCipher(deriveClientSealKey(sessionKey))
	c.Assert(err, IsNil)
	_, err = unsealMessage(cipher, signKey, tamperedSig, ciphertext)
	c.Assert(err, ErrorMatches, "ntlmssp: signature mismatch")
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
