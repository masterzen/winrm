package winrm

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec
	"encoding/binary"

	ntlmssp "github.com/Azure/go-ntlmssp"
	. "gopkg.in/check.v1"
)

// ntlmMicVarFieldPositions lists, independently of ntlmVarFieldOffsetPositions
// in ntlm_mic.go, the byte position of each varField's 2-byte length
// subfield and 4-byte BufferOffset subfield in the fixed 64-byte
// AUTHENTICATE_MESSAGE header (MS-NLMP §2.2.1.3). Kept as a separate literal
// here (not a shared reference to the production table) so a regression in
// the production table's values doesn't silently pass its own test.
var ntlmMicVarFieldPositions = []struct{ lenPos, offsetPos int }{
	{12, 16}, // LmChallengeResponse
	{20, 24}, // NtChallengeResponse
	{28, 32}, // DomainName
	{36, 40}, // UserName
	{44, 48}, // Workstation
	{52, 56}, // SessionKey
}

// ntlmMicBuildAVPair encodes one AV_PAIR (MS-NLMP §2.2.2.1): AvId(u16 LE),
// AvLen(u16 LE), Value.
func ntlmMicBuildAVPair(avID uint16, value []byte) []byte {
	header := make([]byte, 4)
	binary.LittleEndian.PutUint16(header[0:2], avID)
	binary.LittleEndian.PutUint16(header[2:4], uint16(len(value))) //nolint:gosec // test fixture values are small.
	return append(header, value...)
}

// ntlmMicBuildTargetInfo hand-builds a minimal TargetInfo blob (MS-NLMP
// §2.2.2.1). It always includes an MsvAvNbComputerName pair so patch tests
// can confirm unrelated pairs are left untouched, optionally an
// MsvAvTimestamp pair, and optionally an MsvAvFlags pair carrying
// flagsValue. It always terminates with MsvAvEOL.
func ntlmMicBuildTargetInfo(includeTimestamp, includeFlags bool, flagsValue uint32) (blob, computerName []byte) {
	computerName = []byte{0x57, 0x00, 0x52, 0x00, 0x4b, 0x00} // arbitrary bytes standing in for a UTF-16LE computer name
	blob = append(blob, ntlmMicBuildAVPair(ntlmAvIDMsvAvNbComputerNameForTest, computerName)...)
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
	blob = append(blob, ntlmMicBuildAVPair(ntlmAvIDMsvAvEOL, nil)...)
	return blob, computerName
}

// ntlmAvIDMsvAvNbComputerNameForTest is MsvAvNbComputerName (MS-NLMP
// §2.2.2.1 AV_PAIR IDs), used only to build a synthetic "other pair" for the
// patch tests below. It's not otherwise referenced by production code.
const ntlmAvIDMsvAvNbComputerNameForTest = 1

// ntlmMicBuildChallenge hand-builds a minimal CHALLENGE_MESSAGE (MS-NLMP
// §2.2.1.2): fixed 48-byte header, no TargetName payload, and targetInfo (if
// non-nil) appended as the TargetInfo payload.
func ntlmMicBuildChallenge(negotiateFlags uint32, targetInfo []byte) []byte {
	buf := make([]byte, 48)
	copy(buf[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(buf[8:12], 2) // MessageType
	// TargetName varField left zero.
	binary.LittleEndian.PutUint32(buf[20:24], negotiateFlags)
	copy(buf[24:32], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}) // ServerChallenge
	// reserved [32:40] left zero.
	if len(targetInfo) > 0 {
		binary.LittleEndian.PutUint16(buf[40:42], uint16(len(targetInfo))) //nolint:gosec // test fixture values are small.
		binary.LittleEndian.PutUint16(buf[42:44], uint16(len(targetInfo))) //nolint:gosec // test fixture values are small.
		binary.LittleEndian.PutUint32(buf[44:48], 48)
		buf = append(buf, targetInfo...)
	}
	return buf
}

// TestNtlmPatchChallengeForMICNoTimestampIsNoop checks that a CHALLENGE
// whose TargetInfo has no MsvAvTimestamp pair is returned unmodified, with
// micRequired false (MS-NLMP §3.1.5.1.2 only asks for a MIC when a
// timestamp is present).
func (s *WinRMSuite) TestNtlmPatchChallengeForMICNoTimestampIsNoop(c *C) {
	targetInfo, _ := ntlmMicBuildTargetInfo(false, false, 0)
	challenge := ntlmMicBuildChallenge(0x00080005, targetInfo)

	patched, micRequired, err := ntlmPatchChallengeForMIC(challenge)
	c.Assert(err, IsNil)
	c.Assert(micRequired, Equals, false)
	c.Assert(patched, DeepEquals, challenge)
}

// TestNtlmPatchChallengeForMICEmptyTargetInfoIsNoop checks the length==0
// TargetInfo case (no AV-pairs at all, not even EOL) separately from the
// no-timestamp case above.
func (s *WinRMSuite) TestNtlmPatchChallengeForMICEmptyTargetInfoIsNoop(c *C) {
	challenge := ntlmMicBuildChallenge(0x00080005, nil)

	patched, micRequired, err := ntlmPatchChallengeForMIC(challenge)
	c.Assert(err, IsNil)
	c.Assert(micRequired, Equals, false)
	c.Assert(patched, DeepEquals, challenge)
}

// TestNtlmPatchChallengeForMICAddsFlagsWhenAbsent checks the core case: a
// timestamp is present but MsvAvFlags is not, so ntlmPatchChallengeForMIC
// must splice in a new MsvAvFlags pair with bit 0x2 set, leaving every other
// pair (including the timestamp and the unrelated computer-name pair) and
// the terminating EOL untouched.
func (s *WinRMSuite) TestNtlmPatchChallengeForMICAddsFlagsWhenAbsent(c *C) {
	targetInfo, computerName := ntlmMicBuildTargetInfo(true, false, 0)
	challenge := ntlmMicBuildChallenge(0x00080005, targetInfo)

	patched, micRequired, err := ntlmPatchChallengeForMIC(challenge)
	c.Assert(err, IsNil)
	c.Assert(micRequired, Equals, true)

	offset, length, err := ntlmChallengeTargetInfo(patched)
	c.Assert(err, IsNil)
	c.Assert(length, Equals, len(targetInfo)+8) // one new 8-byte AV_PAIR spliced in
	patchedTargetInfo := patched[offset : offset+length]

	var sawComputerName, sawTimestamp, sawFlags, sawEOL bool
	var flagsValue uint32
	var gotComputerName []byte
	err = ntlmWalkAVPairs(patchedTargetInfo, func(avID uint16, value []byte, _ int) bool {
		switch avID {
		case ntlmAvIDMsvAvNbComputerNameForTest:
			sawComputerName = true
			gotComputerName = append([]byte(nil), value...)
		case ntlmAvIDMsvAvTimestamp:
			sawTimestamp = true
		case ntlmAvIDMsvAvFlags:
			sawFlags = true
			flagsValue = binary.LittleEndian.Uint32(value)
		case ntlmAvIDMsvAvEOL:
			sawEOL = true
		}
		return false
	})
	c.Assert(err, IsNil)
	c.Assert(sawComputerName, Equals, true)
	c.Assert(gotComputerName, DeepEquals, computerName)
	c.Assert(sawTimestamp, Equals, true)
	c.Assert(sawFlags, Equals, true)
	c.Assert(flagsValue, Equals, uint32(ntlmAvFlagMICPresent))
	c.Assert(sawEOL, Equals, true)
}

// TestNtlmPatchChallengeForMICSetsBitOnExistingFlags checks that when
// MsvAvFlags is already present with some other bit set, the patch ORs in
// bit 0x2 in place, keeping the blob length (and thus the TargetInfo
// varField's Len/BufferOffset) unchanged.
func (s *WinRMSuite) TestNtlmPatchChallengeForMICSetsBitOnExistingFlags(c *C) {
	targetInfo, _ := ntlmMicBuildTargetInfo(true, true, 0x00000001)
	challenge := ntlmMicBuildChallenge(0x00080005, targetInfo)

	patched, micRequired, err := ntlmPatchChallengeForMIC(challenge)
	c.Assert(err, IsNil)
	c.Assert(micRequired, Equals, true)

	offset, length, err := ntlmChallengeTargetInfo(patched)
	c.Assert(err, IsNil)
	c.Assert(length, Equals, len(targetInfo)) // unchanged: MsvAvFlags patched in place

	patchedTargetInfo := patched[offset : offset+length]
	var sawFlags bool
	var flagsValue uint32
	err = ntlmWalkAVPairs(patchedTargetInfo, func(avID uint16, value []byte, _ int) bool {
		if avID == ntlmAvIDMsvAvFlags {
			sawFlags = true
			flagsValue = binary.LittleEndian.Uint32(value)
		}
		return false
	})
	c.Assert(err, IsNil)
	c.Assert(sawFlags, Equals, true)
	c.Assert(flagsValue, Equals, uint32(0x00000001|ntlmAvFlagMICPresent))
}

// TestNtlmPatchChallengeForMICMalformedFlagsTreatedAsAbsent checks that an
// MsvAvFlags AV-pair whose declared length isn't the required 4 bytes is
// never trusted for its offset. Before the fix, ntlmPatchChallengeForMIC
// would record this pair's offset and later blindly read (and OR/write) 4
// bytes there regardless of its real declared length; here that offset lands
// right at the start of the terminating MsvAvEOL pair, so trusting it would
// read and overwrite the EOL pair's own header bytes, corrupting the
// TargetInfo blob. The fix must instead treat the malformed pair as if
// MsvAvFlags were absent altogether (see
// TestNtlmPatchChallengeForMICAddsFlagsWhenAbsent), leaving it and the EOL
// pair untouched and appending a fresh, well-formed MsvAvFlags pair.
func (s *WinRMSuite) TestNtlmPatchChallengeForMICMalformedFlagsTreatedAsAbsent(c *C) {
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, 132000000000000000)

	var targetInfo []byte
	targetInfo = append(targetInfo, ntlmMicBuildAVPair(ntlmAvIDMsvAvTimestamp, ts)...)
	// A malformed MsvAvFlags pair: AvLen 0 instead of the required 4, whose
	// value offset lands exactly where the terminating MsvAvEOL pair
	// starts -- there is no room for a real 4-byte value here.
	targetInfo = append(targetInfo, ntlmMicBuildAVPair(ntlmAvIDMsvAvFlags, nil)...)
	targetInfo = append(targetInfo, ntlmMicBuildAVPair(ntlmAvIDMsvAvEOL, nil)...)

	challenge := ntlmMicBuildChallenge(0x00080005, targetInfo)

	patched, micRequired, err := ntlmPatchChallengeForMIC(challenge)
	c.Assert(err, IsNil)
	c.Assert(micRequired, Equals, true)

	offset, length, err := ntlmChallengeTargetInfo(patched)
	c.Assert(err, IsNil)
	c.Assert(length, Equals, len(targetInfo)+8) // treated as absent: a fresh pair was appended
	patchedTargetInfo := patched[offset : offset+length]

	var sawTimestamp, sawGoodFlags, sawEOL bool
	var malformedFlagsSeen int
	var goodFlagsValue uint32
	err = ntlmWalkAVPairs(patchedTargetInfo, func(avID uint16, value []byte, _ int) bool {
		switch avID {
		case ntlmAvIDMsvAvTimestamp:
			sawTimestamp = true
		case ntlmAvIDMsvAvFlags:
			if len(value) == 4 {
				sawGoodFlags = true
				goodFlagsValue = binary.LittleEndian.Uint32(value)
			} else {
				malformedFlagsSeen++
			}
		case ntlmAvIDMsvAvEOL:
			sawEOL = true
		}
		return false
	})
	c.Assert(err, IsNil)
	c.Assert(sawTimestamp, Equals, true)
	c.Assert(malformedFlagsSeen, Equals, 1) // the malformed pair is left untouched, not corrupted
	c.Assert(sawGoodFlags, Equals, true)
	c.Assert(goodFlagsValue, Equals, uint32(ntlmAvFlagMICPresent))
	c.Assert(sawEOL, Equals, true)
}

// TestNtlmAttachMICPreservesAuthenticatePayloadFields is the offset-math
// regression test: it drives a real AUTHENTICATE message through the actual
// vendored ntlmssp.NewAuthenticateMessage (built from a patched CHALLENGE
// with a timestamp), runs it through ntlmAttachMIC, then independently
// re-parses the patched token by hand -- walking all six varFields via
// their now-shifted offsets -- and checks every payload field's bytes are
// byte-identical to what they were before patching.
func (s *WinRMSuite) TestNtlmAttachMICPreservesAuthenticatePayloadFields(c *C) {
	targetInfo, _ := ntlmMicBuildTargetInfo(true, false, 0)
	negotiateFlags := uint32(ntlmTestNegotiateUnicode | ntlmNegotiateSign | ntlmNegotiateSeal |
		ntlmNegotiateExtendedSessionSecurity | ntlmNegotiate128 | ntlmNegotiateKeyExch)
	challengeToken := ntlmMicBuildChallenge(negotiateFlags, targetInfo)

	patchedChallenge, micRequired, err := ntlmPatchChallengeForMIC(challengeToken)
	c.Assert(err, IsNil)
	c.Assert(micRequired, Equals, true)

	negotiateToken, err := ntlmssp.NewNegotiateMessageWithOptions(ntlmssp.NegotiateMessageOptions{RequestSealing: true})
	c.Assert(err, IsNil)

	var exportedSessionKey []byte
	authenticateToken, err := ntlmssp.NewAuthenticateMessage(patchedChallenge, ntlmTestUsername, ntlmTestPassword, &ntlmssp.AuthenticateMessageOptions{
		ExportedSessionKey: &exportedSessionKey,
	})
	c.Assert(err, IsNil)
	c.Assert(len(authenticateToken) >= 64, Equals, true)

	type payload struct {
		length int
		bytes  []byte
	}
	originals := make([]payload, len(ntlmMicVarFieldPositions))
	for i, f := range ntlmMicVarFieldPositions {
		length := int(binary.LittleEndian.Uint16(authenticateToken[f.lenPos : f.lenPos+2]))
		offset := int(binary.LittleEndian.Uint32(authenticateToken[f.offsetPos : f.offsetPos+4]))
		var b []byte
		if length > 0 {
			b = append([]byte(nil), authenticateToken[offset:offset+length]...)
		}
		originals[i] = payload{length: length, bytes: b}
	}

	micToken, err := ntlmAttachMIC(negotiateToken, challengeToken, authenticateToken, exportedSessionKey)
	c.Assert(err, IsNil)
	c.Assert(len(micToken), Equals, len(authenticateToken)+16)

	for i, f := range ntlmMicVarFieldPositions {
		length := int(binary.LittleEndian.Uint16(micToken[f.lenPos : f.lenPos+2]))
		c.Assert(length, Equals, originals[i].length)
		if length == 0 {
			continue // don't assert anything about a zero-length field's BufferOffset
		}
		offset := int(binary.LittleEndian.Uint32(micToken[f.offsetPos : f.offsetPos+4]))
		got := micToken[offset : offset+length]
		c.Assert(got, DeepEquals, originals[i].bytes)
	}

	// The MIC itself must have actually been written (not left as the
	// zeroed placeholder ntlmAttachMIC starts with).
	allZero := true
	for _, b := range micToken[64:80] {
		if b != 0 {
			allZero = false
			break
		}
	}
	c.Assert(allZero, Equals, false)
}

// ntlmMicBuildSyntheticAuthenticateToken hand-builds a structurally valid
// AUTHENTICATE_MESSAGE fixed header plus deterministic payload bytes, sized
// by ntChallengeResponseLen. DomainName and Workstation are given Len==0
// but a nonzero BufferOffset (matching the real vendored encoder's
// behavior, see ntlm_mic.go's ntlmAttachMIC doc comment), to exercise the
// "skip zero-length fields, don't assume BufferOffset is 0" path.
func ntlmMicBuildSyntheticAuthenticateToken(ntChallengeResponseLen int) []byte {
	const lmLen = 24
	const userLen = 6
	const sessionKeyLen = 16

	header := make([]byte, 64)
	copy(header[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(header[8:12], 3) // MessageType = AUTHENTICATE

	ptr := 64
	setField := func(lenPos, offsetPos, length int) {
		binary.LittleEndian.PutUint16(header[lenPos:lenPos+2], uint16(length))    //nolint:gosec // test fixture values are small.
		binary.LittleEndian.PutUint16(header[lenPos+2:lenPos+4], uint16(length))  //nolint:gosec // test fixture values are small.
		binary.LittleEndian.PutUint32(header[offsetPos:offsetPos+4], uint32(ptr)) //nolint:gosec // test fixture values are small.
		ptr += length
	}
	setField(12, 16, lmLen)                  // LmChallengeResponse
	setField(20, 24, ntChallengeResponseLen) // NtChallengeResponse
	setField(28, 32, 0)                      // DomainName: zero length, nonzero offset
	setField(36, 40, userLen)                // UserName
	setField(44, 48, 0)                      // Workstation: zero length, nonzero offset
	setField(52, 56, sessionKeyLen)          // SessionKey
	binary.LittleEndian.PutUint32(header[60:64], 0x00000005)

	payload := make([]byte, ptr-64)
	for i := range payload {
		payload[i] = byte(i + 1)
	}

	return append(header, payload...)
}

// TestNtlmAttachMICHMACMatchesIndependentComputation checks ntlmAttachMIC's
// own HMAC-MD5 value against one computed independently in the test with
// crypto/hmac and crypto/md5 directly (not ntlmHmacMd5, to keep the check
// independent of the implementation under test), over two differently sized
// AUTHENTICATE preimages -- standing in for "MsvAvFlags was already present
// in the CHALLENGE" (shorter NtChallengeResponse) versus "MsvAvFlags had to
// be added" (NtChallengeResponse 8 bytes longer, since its embedded
// TargetInfo copy grew) -- which produce different-length withMIC inputs.
func (s *WinRMSuite) TestNtlmAttachMICHMACMatchesIndependentComputation(c *C) {
	negotiateToken := []byte("negotiate-token-fixture")
	challengeToken := []byte("challenge-token-fixture-bytes")
	exportedSessionKey := []byte("0123456789abcdef")

	for _, ntChallengeResponseLen := range []int{48, 56} {
		authenticateToken := ntlmMicBuildSyntheticAuthenticateToken(ntChallengeResponseLen)

		micToken, err := ntlmAttachMIC(negotiateToken, challengeToken, authenticateToken, exportedSessionKey)
		c.Assert(err, IsNil)

		withMIC := append(append(append([]byte{}, authenticateToken[:64]...), make([]byte, 16)...), authenticateToken[64:]...)
		for _, pos := range ntlmMicVarFieldPositions {
			length := binary.LittleEndian.Uint16(withMIC[pos.lenPos : pos.lenPos+2])
			if length == 0 {
				continue
			}
			off := binary.LittleEndian.Uint32(withMIC[pos.offsetPos : pos.offsetPos+4])
			binary.LittleEndian.PutUint32(withMIC[pos.offsetPos:pos.offsetPos+4], off+16)
		}

		mac := hmac.New(md5.New, exportedSessionKey)
		mac.Write(negotiateToken)
		mac.Write(challengeToken)
		mac.Write(withMIC)
		want := mac.Sum(nil)

		c.Assert(micToken[64:80], DeepEquals, want)
	}
}

// TestNtlmAttachMICRejectsNegotiateVersion checks that ntlmAttachMIC refuses
// to proceed when the AUTHENTICATE_MESSAGE's NegotiateFlags (bytes [60:64],
// inside the region this function already requires present) carries
// NTLMSSP_NEGOTIATE_VERSION. The fixed 64-byte header offsets this function
// relies on don't account for the optional 8-byte Version block that flag
// implies (MS-NLMP §2.2.2.5); today's Azure/go-ntlmssp never sets it, but if
// it ever did, trusting the 64-byte layout would silently splice the MIC and
// rewrite BufferOffsets at the wrong byte positions rather than erroring out.
func (s *WinRMSuite) TestNtlmAttachMICRejectsNegotiateVersion(c *C) {
	negotiateToken := []byte("negotiate-token-fixture")
	challengeToken := []byte("challenge-token-fixture-bytes")
	exportedSessionKey := []byte("0123456789abcdef")

	authenticateToken := ntlmMicBuildSyntheticAuthenticateToken(48)
	binary.LittleEndian.PutUint32(authenticateToken[60:64], 0x00000005|ntlmNegotiateVersion)

	_, err := ntlmAttachMIC(negotiateToken, challengeToken, authenticateToken, exportedSessionKey)
	c.Assert(err, ErrorMatches, ".*NTLMSSP_NEGOTIATE_VERSION.*")
}
