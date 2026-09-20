package winrm

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec
	"crypto/rc4"
	"errors"
	"slices"
)

// NTLM signing/sealing key derivation magic constants (MS-NLMP §3.4.5).
const (
	ntlmClientToServerSigning = "session key to client-to-server signing key magic constant"
	ntlmClientToServerSealing = "session key to client-to-server sealing key magic constant"
	ntlmServerToClientSigning = "session key to server-to-client signing key magic constant"
	ntlmServerToClientSealing = "session key to server-to-client sealing key magic constant"
	ntlmVersionMagic          = "\x01\x00\x00\x00"
)

// deriveClientSignKey derives the client-to-server signing key from the exported session key (MS-NLMP §3.4.5.2).
func deriveClientSignKey(sessionKey []byte) []byte {
	return ntlmDerivedKey(sessionKey, ntlmClientToServerSigning)
}

// deriveClientSealKey derives the client-to-server sealing key from the exported session key (MS-NLMP §3.4.5.3).
func deriveClientSealKey(sessionKey []byte) []byte {
	return ntlmDerivedKey(sessionKey, ntlmClientToServerSealing)
}

// deriveServerSignKey derives the server-to-client signing key from the exported session key (MS-NLMP §3.4.5.2).
func deriveServerSignKey(sessionKey []byte) []byte {
	return ntlmDerivedKey(sessionKey, ntlmServerToClientSigning)
}

// deriveServerSealKey derives the server-to-client sealing key from the exported session key (MS-NLMP §3.4.5.3).
func deriveServerSealKey(sessionKey []byte) []byte {
	return ntlmDerivedKey(sessionKey, ntlmServerToClientSealing)
}

// sealMessage encrypts plaintext using the RC4 sealing cipher and computes the
// NTLMSSP_MESSAGE_SIGNATURE for it (MS-NLMP §3.4.3, §3.4.4).
//
// cipher must be the caller's persistent client (or server) sealing cipher. Its
// internal state advances with each call, so the same cipher must be reused in
// order for every message in the session (MS-NLMP §3.4 CONNECTION mode).
// seqNum is the zero-based sequence number of this message and must increment by
// one for every message sealed with this cipher.
func sealMessage(cipher *rc4.Cipher, signKey []byte, seqNum uint32, plaintext []byte) (ciphertext, signature []byte) {
	seq := ntlmSeqBytes(seqNum)
	ciphertext = make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	signature = ntlmSign(cipher, signKey, seq, plaintext)
	return ciphertext, signature
}

// unsealMessage decrypts ciphertext using the RC4 sealing cipher and verifies it
// against signature (MS-NLMP §3.4.3, §3.4.4).
//
// cipher must be the caller's persistent sealing cipher for the sender, used in
// CONNECTION mode (see sealMessage). returns an error if signature does not match.
func unsealMessage(cipher *rc4.Cipher, signKey []byte, signature, ciphertext []byte) ([]byte, error) {
	if len(signature) != 16 {
		return nil, errors.New("ntlmssp: signature must be 16 bytes")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)
	expected := ntlmSign(cipher, signKey, signature[12:16], plaintext)
	if !hmac.Equal(signature, expected) {
		return nil, errors.New("ntlmssp: signature mismatch")
	}
	return plaintext, nil
}

func ntlmDerivedKey(sessionKey []byte, magicConstant string) []byte {
	keyIn := slices.Concat(sessionKey, append([]byte(magicConstant), 0))
	sum := md5.Sum(keyIn) //nolint:gosec
	return sum[:]
}

func ntlmSeqBytes(seqNum uint32) []byte {
	return []byte{byte(seqNum), byte(seqNum >> 8), byte(seqNum >> 16), byte(seqNum >> 24)}
}

func ntlmSign(sealCipher *rc4.Cipher, signKey []byte, seq []byte, plaintext []byte) []byte {
	encHmac := make([]byte, 8)
	sealCipher.XORKeyStream(encHmac, ntlmHmacMd5(signKey, append(seq, plaintext...))[:8])
	return append(append([]byte(ntlmVersionMagic), encHmac...), seq...)
}

func ntlmHmacMd5(key []byte, data ...[]byte) []byte {
	h := hmac.New(md5.New, key) //nolint:gosec
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}
