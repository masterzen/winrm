package winrm

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // MS-NLMP's MIC is HMAC-MD5.
	"encoding/binary"
	"fmt"

	. "gopkg.in/check.v1"
)

// The MIC itself is produced by Azure/go-ntlmssp (AuthenticateMessageOptions.
// NegotiateMessage). These tests check, independently of that library, that
// the AUTHENTICATE message negotiateAzureNTLMSessionKey sends carries a MIC
// that a server would accept (MS-NLMP §2.2.1.3, §3.1.5.1.2).

// NTLM AV_PAIR IDs relevant to the MIC (MS-NLMP §2.2.2.1).
const (
	ntlmAvIDMsvAvEOL            = 0
	ntlmAvIDMsvAvNbComputerName = 1
	ntlmAvIDMsvAvFlags          = 6
	ntlmAvIDMsvAvTimestamp      = 7
)

// ntlmAvFlagMICPresent is bit 0x2 of the MsvAvFlags AV-pair value (MS-NLMP
// §2.2.2.1).
const ntlmAvFlagMICPresent = 0x00000002

// ntlmNegotiateVersion is NTLMSSP_NEGOTIATE_VERSION (MS-NLMP §2.2.2.5).
const ntlmNegotiateVersion = 0x02000000

// ntlmVersionBlock is the Version field (MS-NLMP §2.2.2.10) go-ntlmssp
// writes when VERSION is negotiated: Windows 7 SP1, NTLM revision 15.
var ntlmVersionBlock = [8]byte{6, 1, 0xb1, 0x1d, 0, 0, 0, 0x0f}

// ntlmMicVarFieldPositions lists the byte position of each varField's
// 2-byte Len and 4-byte BufferOffset in the AUTHENTICATE_MESSAGE header
// (MS-NLMP §2.2.1.3).
var ntlmMicVarFieldPositions = []struct{ lenPos, offsetPos int }{
	{12, 16}, // LmChallengeResponse
	{20, 24}, // NtChallengeResponse
	{28, 32}, // DomainName
	{36, 40}, // UserName
	{44, 48}, // Workstation
	{52, 56}, // SessionKey
}

// ntlmWalkAVPairs calls visit for each AV_PAIR in targetInfo (MS-NLMP
// §2.2.2.1), up to and including MsvAvEOL, or until visit returns true.
func ntlmWalkAVPairs(targetInfo []byte, visit func(avID uint16, value []byte, valueOffsetInBlob int) (stop bool)) error {
	pos := 0
	for {
		if pos+4 > len(targetInfo) {
			return fmt.Errorf("AV_PAIR header extends beyond TargetInfo blob at offset %d (%d bytes total)", pos, len(targetInfo))
		}
		avID := binary.LittleEndian.Uint16(targetInfo[pos : pos+2])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[pos+2 : pos+4]))
		valueOffset := pos + 4
		if valueOffset+avLen > len(targetInfo) {
			return fmt.Errorf("AV_PAIR value extends beyond TargetInfo blob at offset %d (len %d, blob %d bytes)", valueOffset, avLen, len(targetInfo))
		}
		if visit(avID, targetInfo[valueOffset:valueOffset+avLen], valueOffset) || avID == ntlmAvIDMsvAvEOL {
			return nil
		}
		pos = valueOffset + avLen
	}
}

// ntlmMicBuildAVPair encodes one AV_PAIR (MS-NLMP §2.2.2.1).
func ntlmMicBuildAVPair(avID uint16, value []byte) []byte {
	header := make([]byte, 4)
	binary.LittleEndian.PutUint16(header[0:2], avID)
	binary.LittleEndian.PutUint16(header[2:4], uint16(len(value))) //nolint:gosec // test fixture values are small.
	return append(header, value...)
}

// ntlmMicBuildTargetInfo hand-builds a minimal TargetInfo blob: an
// MsvAvNbComputerName pair, optionally an MsvAvTimestamp pair, optionally an
// MsvAvFlags pair carrying flagsValue, then MsvAvEOL.
func ntlmMicBuildTargetInfo(includeTimestamp, includeFlags bool, flagsValue uint32) []byte {
	var blob []byte
	blob = append(blob, ntlmMicBuildAVPair(ntlmAvIDMsvAvNbComputerName, []byte{0x57, 0x00, 0x52, 0x00, 0x4b, 0x00})...)
	if includeTimestamp {
		ts := make([]byte, 8)
		binary.LittleEndian.PutUint64(ts, 132000000000000000)
		blob = append(blob, ntlmMicBuildAVPair(ntlmAvIDMsvAvTimestamp, ts)...)
	}
	if includeFlags {
		v := make([]byte, 4)
		binary.LittleEndian.PutUint32(v, flagsValue)
		blob = append(blob, ntlmMicBuildAVPair(ntlmAvIDMsvAvFlags, v)...)
	}
	return append(blob, ntlmMicBuildAVPair(ntlmAvIDMsvAvEOL, nil)...)
}

// ntlmMicBuildChallenge hand-builds a minimal CHALLENGE_MESSAGE (MS-NLMP
// §2.2.1.2) with no TargetName and targetInfo as the TargetInfo payload.
func ntlmMicBuildChallenge(negotiateFlags uint32, targetInfo []byte) []byte {
	buf := make([]byte, 48)
	copy(buf[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(buf[8:12], 2) // MessageType
	binary.LittleEndian.PutUint32(buf[20:24], negotiateFlags)
	copy(buf[24:32], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}) // ServerChallenge
	if len(targetInfo) > 0 {
		binary.LittleEndian.PutUint16(buf[40:42], uint16(len(targetInfo))) //nolint:gosec // test fixture values are small.
		binary.LittleEndian.PutUint16(buf[42:44], uint16(len(targetInfo))) //nolint:gosec // test fixture values are small.
		binary.LittleEndian.PutUint32(buf[44:48], 48)
		buf = append(buf, targetInfo...)
	}
	return buf
}

const ntlmMicSealingFlags = uint32(ntlmTestNegotiateUnicode | ntlmNegotiateSign | ntlmNegotiateSeal |
	ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate128 | ntlmNegotiateKeyExch)

// ntlmMicHandshake runs negotiateAzureNTLMSessionKey against a fixed
// CHALLENGE and returns what was sent.
func ntlmMicHandshake(c *C, challenge []byte) (negotiate, authenticate, sessionKey []byte) {
	authenticate, sessionKey, _, err := negotiateAzureNTLMSessionKey(ntlmTestUsername, ntlmTestPassword, func(token []byte) ([]byte, error) {
		negotiate = token
		return challenge, nil
	})
	c.Assert(err, IsNil)
	c.Assert(len(authenticate) >= 64, Equals, true)
	return negotiate, authenticate, sessionKey
}

// ntlmMicAssertFieldsInBounds checks that every varField's payload lies at
// or after payloadStart and within the token. Windows's NTLM SSP validates
// these bounds even for zero-length fields and rejects the message with
// SEC_E_INVALID_TOKEN otherwise.
func ntlmMicAssertFieldsInBounds(c *C, authenticate []byte, payloadStart int) {
	for _, f := range ntlmMicVarFieldPositions {
		length := int(binary.LittleEndian.Uint16(authenticate[f.lenPos : f.lenPos+2]))
		offset := int(binary.LittleEndian.Uint32(authenticate[f.offsetPos : f.offsetPos+4]))
		c.Assert(offset >= payloadStart, Equals, true, Commentf("field at %d: offset %d < %d", f.offsetPos, offset, payloadStart))
		c.Assert(offset+length <= len(authenticate), Equals, true, Commentf("field at %d out of bounds", f.offsetPos))
	}
}

// TestNtlmMICAttachedWhenTimestampPresent checks that when the CHALLENGE
// carries an MsvAvTimestamp, the AUTHENTICATE message has a Version block
// and a MIC that verifies under the exported session key, and that its
// NtChallengeResponse advertises MsvAvFlags MIC-present.
func (s *WinRMSuite) TestNtlmMICAttachedWhenTimestampPresent(c *C) {
	cases := []struct {
		name           string
		includeFlags   bool
		flagsValue     uint32
		negotiateFlags uint32
	}{
		{"flags-absent", false, 0, ntlmMicSealingFlags},
		{"flags-present", true, 0x00000001, ntlmMicSealingFlags},
		{"version-negotiated", false, 0, ntlmMicSealingFlags | ntlmNegotiateVersion},
	}
	for _, tc := range cases {
		comment := Commentf("case %q", tc.name)
		challenge := ntlmMicBuildChallenge(tc.negotiateFlags, ntlmMicBuildTargetInfo(true, tc.includeFlags, tc.flagsValue))
		negotiate, authenticate, sessionKey := ntlmMicHandshake(c, challenge)

		const headerEnd = 72 // fixed fields + Version
		c.Assert(len(authenticate) >= headerEnd+16, Equals, true, comment)
		ntlmMicAssertFieldsInBounds(c, authenticate, headerEnd+16)

		authFlags := binary.LittleEndian.Uint32(authenticate[60:64])
		if tc.negotiateFlags&ntlmNegotiateVersion != 0 {
			c.Assert(authFlags&ntlmNegotiateVersion, Equals, uint32(ntlmNegotiateVersion), comment)
			c.Assert(authenticate[64:72], DeepEquals, ntlmVersionBlock[:], comment)
		} else {
			// MS-NLMP §2.2.1.3: Version MUST be zero when not negotiated.
			c.Assert(authenticate[64:72], DeepEquals, make([]byte, 8), comment)
		}

		zeroed := append([]byte(nil), authenticate...)
		copy(zeroed[headerEnd:headerEnd+16], make([]byte, 16))
		mac := hmac.New(md5.New, sessionKey)
		mac.Write(negotiate)
		mac.Write(challenge)
		mac.Write(zeroed)
		c.Assert(authenticate[headerEnd:headerEnd+16], DeepEquals, mac.Sum(nil), comment)

		ntResponse, _, _, err := ntlmTestParseAuthenticateMessage(authenticate)
		c.Assert(err, IsNil, comment)
		c.Assert(len(ntResponse) > 44, Equals, true, comment)
		var flags uint32
		var sawFlags bool
		c.Assert(ntlmWalkAVPairs(ntResponse[44:], func(id uint16, v []byte, _ int) bool {
			if id == ntlmAvIDMsvAvFlags && len(v) == 4 {
				sawFlags, flags = true, binary.LittleEndian.Uint32(v)
			}
			return false
		}), IsNil, comment)
		c.Assert(sawFlags, Equals, true, comment)
		c.Assert(flags, Equals, tc.flagsValue|ntlmAvFlagMICPresent, comment)
	}
}

// TestNtlmMICOmittedWithoutTimestamp checks that without an MsvAvTimestamp
// no MIC (and so no Version block) is sent: the AUTHENTICATE message keeps
// its plain 64-byte header and does not claim NTLMSSP_NEGOTIATE_VERSION.
func (s *WinRMSuite) TestNtlmMICOmittedWithoutTimestamp(c *C) {
	challenge := ntlmMicBuildChallenge(ntlmMicSealingFlags|ntlmNegotiateVersion, ntlmMicBuildTargetInfo(false, false, 0))
	_, authenticate, _ := ntlmMicHandshake(c, challenge)

	ntlmMicAssertFieldsInBounds(c, authenticate, 64)
	lmOffset := binary.LittleEndian.Uint32(authenticate[16:20])
	c.Assert(lmOffset, Equals, uint32(64))
	c.Assert(binary.LittleEndian.Uint32(authenticate[60:64])&ntlmNegotiateVersion, Equals, uint32(0))
}
