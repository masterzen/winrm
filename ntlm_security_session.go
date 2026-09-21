package winrm

import (
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/Azure/go-ntlmssp"
)

// NTLM NEGOTIATE flags (MS-NLMP §2.2.2.5).
const (
	ntlmNegotiateSign                    = 0x00000010
	ntlmNegotiateSeal                    = 0x00000020
	ntlmNegotiate56                      = 0x80000000
	ntlmNegotiate128                     = 0x20000000
	ntlmNegotiateKeyExch                 = 0x40000000
	ntlmNegotiateExtendedSessionSecurity = 0x00080000
)

type ntlmKeyStrength int

const (
	ntlmKey128Bit ntlmKeyStrength = 128
	ntlmKey56Bit  ntlmKeyStrength = 56
	ntlmKey40Bit  ntlmKeyStrength = 40
)

// ntlmChallengeNegotiateFlags reads NegotiateFlags from an NTLM
// CHALLENGE_MESSAGE (MS-NLMP §2.2.1.2). The token must be at least 24 bytes.
func ntlmChallengeNegotiateFlags(challengeToken []byte) (uint32, error) {
	if len(challengeToken) < 24 {
		return 0, fmt.Errorf("ntlmssp: challenge token too short to contain NegotiateFlags: %d bytes", len(challengeToken))
	}
	return binary.LittleEndian.Uint32(challengeToken[20:24]), nil
}

// classifyNTLMKeyStrength maps negotiated flags to a key size (MS-NLMP
// §3.4.5.3). NTLM1 and LM-key mode are not supported.
//
//	ExtendedSessionSecurity && Negotiate128 -> 128-bit
//	ExtendedSessionSecurity && Negotiate56  -> 56-bit
//	ExtendedSessionSecurity (neither flag)  -> 40-bit
//	!ExtendedSessionSecurity                -> error
func classifyNTLMKeyStrength(negotiateFlags uint32) (ntlmKeyStrength, error) {
	if negotiateFlags&ntlmNegotiateExtendedSessionSecurity == 0 {
		return 0, errors.New("ntlmssp: NTLM1/LM-key mode is not supported (extended session security not negotiated)")
	}
	switch {
	case negotiateFlags&ntlmNegotiate128 != 0:
		return ntlmKey128Bit, nil
	case negotiateFlags&ntlmNegotiate56 != 0:
		return ntlmKey56Bit, nil
	default:
		return ntlmKey40Bit, nil
	}
}

// NTLMKeyExchangeOptions controls the minimum accepted NTLM key strength.
// The zero value accepts any strength the server negotiates. This matches
// bodgit/ntlmssp's historical behavior, so existing callers keep working.
// Set MinimumKeyBits to reject weaker keys instead.
type NTLMKeyExchangeOptions struct {
	MinimumKeyBits int
}

func (o NTLMKeyExchangeOptions) satisfiedBy(strength ntlmKeyStrength) bool {
	return o.MinimumKeyBits == 0 || int(strength) >= o.MinimumKeyBits
}

// azureNTLMSecuritySession provides NTLM message confidentiality and
// integrity (MS-NLMP §3.4) from an Azure/go-ntlmssp session key. Its
// Wrap/Unwrap match bodgit/ntlmssp.SecuritySession's shape, so it drops into
// any interface shaped the same way.
type azureNTLMSecuritySession struct {
	outgoingSeal, incomingSeal             *rc4.Cipher
	outgoingSignKey, incomingSignKey       []byte
	outgoingSeqNum, expectedIncomingSeqNum uint32
	// keyExch records whether the server's CHALLENGE_MESSAGE granted
	// NTLMSSP_NEGOTIATE_KEY_EXCH. MS-NLMP §3.4.4.2 requires it to gate
	// whether Wrap/Unwrap RC4-encrypt the signature checksum (see
	// ntlmSign in ntlm_sealing.go); a server can grant
	// NTLMSSP_NEGOTIATE_SEAL without granting key exchange.
	keyExch bool
	// mu serializes Wrap and Unwrap. Different goroutines, for example a
	// command output poll and a stdin write, can call them on the same
	// session at the same time. The sequence counters need this lock to
	// stay correct.
	mu sync.Mutex
}

// newAzureNTLMSecuritySession derives NTLM sealing and signing keys from the
// exported session key and the negotiated flags (MS-NLMP §3.4.5).
//
// Only 128-bit keys are supported. A weaker negotiated strength returns an
// error, never a silently wrong key.
//
// Extended session security is required.
//
// isClient selects the key direction: true for client-to-server as
// outgoing, false for the mirror. This is a client-only library, so
// production code always passes true; the false direction exists so
// tests can construct the peer session and verify Wrap/Unwrap round-trip.
//
// The returned session also records whether negotiateFlags granted
// NTLMSSP_NEGOTIATE_KEY_EXCH, which Wrap/Unwrap need to sign messages
// correctly (MS-NLMP §3.4.4.2).
func newAzureNTLMSecuritySession(sessionKey []byte, negotiateFlags uint32, isClient bool, opts NTLMKeyExchangeOptions) (*azureNTLMSecuritySession, error) {
	strength, err := classifyNTLMKeyStrength(negotiateFlags)
	if err != nil {
		return nil, err
	}
	if strength != ntlmKey128Bit {
		return nil, fmt.Errorf("ntlmssp: %d-bit NTLM keys are not yet supported", int(strength))
	}
	if !opts.satisfiedBy(strength) {
		return nil, fmt.Errorf("ntlmssp: negotiated %d-bit key is below the required minimum of %d bits", int(strength), opts.MinimumKeyBits)
	}

	clientSealCipher, err := rc4.NewCipher(deriveClientSealKey(sessionKey))
	if err != nil {
		return nil, fmt.Errorf("ntlmssp: creating client seal cipher: %w", err)
	}
	serverSealCipher, err := rc4.NewCipher(deriveServerSealKey(sessionKey))
	if err != nil {
		return nil, fmt.Errorf("ntlmssp: creating server seal cipher: %w", err)
	}
	clientSignKey := deriveClientSignKey(sessionKey)
	serverSignKey := deriveServerSignKey(sessionKey)
	keyExch := negotiateFlags&ntlmNegotiateKeyExch != 0

	s := &azureNTLMSecuritySession{keyExch: keyExch}
	if isClient {
		s.outgoingSeal, s.incomingSeal = clientSealCipher, serverSealCipher
		s.outgoingSignKey, s.incomingSignKey = clientSignKey, serverSignKey
	} else {
		s.outgoingSeal, s.incomingSeal = serverSealCipher, clientSealCipher
		s.outgoingSignKey, s.incomingSignKey = serverSignKey, clientSignKey
	}
	return s, nil
}

// Wrap seals b for transmission, returning ciphertext and signature.
func (s *azureNTLMSecuritySession) Wrap(b []byte) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ciphertext, signature := sealMessage(s.outgoingSeal, s.outgoingSignKey, s.outgoingSeqNum, b, s.keyExch)
	s.outgoingSeqNum++
	return ciphertext, signature, nil
}

// Unwrap decrypts and verifies a ciphertext/signature pair.
//
// It checks the sequence number before decrypting, and rejects a replayed
// or reordered message even when its signature is otherwise valid. This
// closes a gap in bodgit/ntlmssp's original design, which trusted the
// sequence number carried inside the signature instead of checking it
// against an expected counter.
func (s *azureNTLMSecuritySession) Unwrap(b, signature []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(signature) < ntlmSignatureLength {
		return nil, errors.New("ntlmssp: signature must be at least 16 bytes")
	}

	gotSeqNum := binary.LittleEndian.Uint32(signature[12:ntlmSignatureLength])
	if gotSeqNum != s.expectedIncomingSeqNum {
		return nil, fmt.Errorf("ntlmssp: unexpected sequence number in signature (got %d, want %d)", gotSeqNum, s.expectedIncomingSeqNum)
	}

	plaintext, err := unsealMessage(s.incomingSeal, s.incomingSignKey, signature, b, s.keyExch)
	if err != nil {
		return nil, err
	}
	s.expectedIncomingSeqNum++
	return plaintext, nil
}

// negotiateAzureNTLMSessionKey runs the NTLM negotiate/challenge/authenticate
// exchange and requests sealing. negotiateChallenge sends the negotiate
// token and returns the server's challenge token; the caller supplies the
// transport (an HTTP header, or a CredSSP TSRequest).
//
// Do not set AuthenticateMessageOptions.RequireSealing. It demands 128-bit
// specifically, which breaks 56/40-bit servers.
func negotiateAzureNTLMSessionKey(username, password string, negotiateChallenge func(negotiateToken []byte) (challengeToken []byte, err error)) (authenticateToken, sessionKey []byte, negotiateFlags uint32, err error) {
	negotiateToken, err := ntlmssp.NewNegotiateMessageWithOptions(ntlmssp.NegotiateMessageOptions{
		RequestSealing: true,
	})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ntlmssp: building NEGOTIATE message: %w", err)
	}

	challengeToken, err := negotiateChallenge(negotiateToken)
	if err != nil {
		return nil, nil, 0, err
	}

	negotiateFlags, err = ntlmChallengeNegotiateFlags(challengeToken)
	if err != nil {
		return nil, nil, 0, err
	}

	var exportedSessionKey []byte
	authenticateToken, err = ntlmssp.NewAuthenticateMessage(challengeToken, username, password, &ntlmssp.AuthenticateMessageOptions{
		ExportedSessionKey: &exportedSessionKey,
	})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ntlmssp: building AUTHENTICATE message: %w", err)
	}

	return authenticateToken, exportedSessionKey, negotiateFlags, nil
}
