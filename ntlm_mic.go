package winrm

import (
	"encoding/binary"
	"fmt"
)

// NTLM AV_PAIR IDs relevant to the MIC (MS-NLMP §2.2.2.1).
const (
	ntlmAvIDMsvAvEOL       = 0
	ntlmAvIDMsvAvFlags     = 6
	ntlmAvIDMsvAvTimestamp = 7
)

// ntlmAvFlagMICPresent is bit 0x2 of the MsvAvFlags AV-pair value: the
// client SHOULD provide a MIC (MS-NLMP §2.2.2.1, §3.1.5.1.2).
const ntlmAvFlagMICPresent = 0x00000002

// ntlmNegotiateVersion is the NTLMSSP_NEGOTIATE_VERSION NEGOTIATE flag
// (MS-NLMP §2.2.2.5, bit 0x02000000). When set, the AUTHENTICATE_MESSAGE
// carries an extra 8-byte Version block between NegotiateFlags and the
// MIC/payload area, which ntlmAttachMIC's fixed 64-byte header offsets do
// not account for.
const ntlmNegotiateVersion = 0x02000000

// ntlmChallengeTargetInfo reads the TargetInfo varField from an NTLM
// CHALLENGE_MESSAGE (MS-NLMP §2.2.1.2): Len uint16 @[40:42], MaxLen uint16
// @[42:44], BufferOffset uint32 @[44:48].
func ntlmChallengeTargetInfo(challengeToken []byte) (offset, length int, err error) {
	if len(challengeToken) < 48 {
		return 0, 0, fmt.Errorf("ntlmssp: challenge token too short to contain TargetInfo: %d bytes", len(challengeToken))
	}
	length = int(binary.LittleEndian.Uint16(challengeToken[40:42]))
	offset = int(binary.LittleEndian.Uint32(challengeToken[44:48]))
	if offset < 0 || length < 0 || offset+length > len(challengeToken) {
		return 0, 0, fmt.Errorf("ntlmssp: TargetInfo field (offset %d, length %d) extends beyond challenge token of %d bytes", offset, length, len(challengeToken))
	}
	return offset, length, nil
}

// ntlmWalkAVPairs walks the AvId(uint16 LE)/AvLen(uint16 LE)/Value sequence
// of an NTLM TargetInfo blob (MS-NLMP §2.2.2.1), calling visit for every
// AV_PAIR encountered, including the terminating MsvAvEOL pair. valueOffsetInBlob
// is the byte offset of the AV_PAIR's Value within targetInfo. Walking stops
// when visit returns true, when an MsvAvEOL pair is reached, or when the
// blob is exhausted. It returns an error if the blob is truncated or
// malformed rather than panicking on an out-of-range slice.
func ntlmWalkAVPairs(targetInfo []byte, visit func(avID uint16, value []byte, valueOffsetInBlob int) (stop bool)) error {
	pos := 0
	for {
		if pos+4 > len(targetInfo) {
			return fmt.Errorf("ntlmssp: AV_PAIR header extends beyond TargetInfo blob at offset %d (%d bytes total)", pos, len(targetInfo))
		}
		avID := binary.LittleEndian.Uint16(targetInfo[pos : pos+2])
		avLen := int(binary.LittleEndian.Uint16(targetInfo[pos+2 : pos+4]))
		valueOffset := pos + 4
		if valueOffset+avLen > len(targetInfo) {
			return fmt.Errorf("ntlmssp: AV_PAIR value extends beyond TargetInfo blob at offset %d (len %d, blob %d bytes)", valueOffset, avLen, len(targetInfo))
		}
		value := targetInfo[valueOffset : valueOffset+avLen]
		if visit(avID, value, valueOffset) {
			return nil
		}
		if avID == ntlmAvIDMsvAvEOL {
			return nil
		}
		pos = valueOffset + avLen
	}
}

// ntlmPatchChallengeForMIC builds a locally patched copy of challengeToken
// with the MsvAvFlags MIC-required bit set in TargetInfo, when the server's
// TargetInfo carries an MsvAvTimestamp AV-pair (MS-NLMP §3.1.5.1.2). The
// original challengeToken is never modified; this patched copy is meant to
// be passed only to ntlmssp.NewAuthenticateMessage so the NtChallengeResponse
// and session key it derives already account for the MIC bit. It is never
// sent on the wire.
//
// micRequired reports whether a MIC must be attached to the AUTHENTICATE
// message (i.e. whether MsvAvTimestamp was present).
func ntlmPatchChallengeForMIC(challengeToken []byte) (patched []byte, micRequired bool, err error) {
	offset, length, err := ntlmChallengeTargetInfo(challengeToken)
	if err != nil {
		return nil, false, err
	}
	if length == 0 {
		return challengeToken, false, nil
	}
	targetInfo := challengeToken[offset : offset+length]

	var (
		hasTimestamp  bool
		hasFlags      bool
		flagsValueOff int
		eolOffset     = length
	)
	if err := ntlmWalkAVPairs(targetInfo, func(avID uint16, value []byte, valueOffsetInBlob int) bool {
		switch avID {
		case ntlmAvIDMsvAvTimestamp:
			hasTimestamp = true
		case ntlmAvIDMsvAvFlags:
			if len(value) != 4 {
				// A malformed MsvAvFlags pair. Treat it as absent rather
				// than trusting its offset: the "MsvAvFlags absent" branch
				// below still sets the MIC bit correctly by inserting a
				// new, well-formed pair.
				return false
			}
			hasFlags = true
			flagsValueOff = valueOffsetInBlob
		case ntlmAvIDMsvAvEOL:
			eolOffset = valueOffsetInBlob - 4 // back up to the start of the EOL AV_PAIR header
		}
		return false
	}); err != nil {
		return nil, false, err
	}

	if !hasTimestamp {
		return challengeToken, false, nil
	}

	var newTargetInfo []byte
	if hasFlags {
		newTargetInfo = append([]byte(nil), targetInfo...)
		flags := binary.LittleEndian.Uint32(newTargetInfo[flagsValueOff : flagsValueOff+4])
		flags |= ntlmAvFlagMICPresent
		binary.LittleEndian.PutUint32(newTargetInfo[flagsValueOff:flagsValueOff+4], flags)
	} else {
		newPair := make([]byte, 8)
		binary.LittleEndian.PutUint16(newPair[0:2], ntlmAvIDMsvAvFlags)
		binary.LittleEndian.PutUint16(newPair[2:4], 4)
		binary.LittleEndian.PutUint32(newPair[4:8], ntlmAvFlagMICPresent)

		newTargetInfo = make([]byte, 0, len(targetInfo)+8)
		newTargetInfo = append(newTargetInfo, targetInfo[:eolOffset]...)
		newTargetInfo = append(newTargetInfo, newPair...)
		newTargetInfo = append(newTargetInfo, targetInfo[eolOffset:]...)
	}

	if len(newTargetInfo) == length {
		patched = append([]byte(nil), challengeToken...)
		copy(patched[offset:offset+length], newTargetInfo)
		return patched, true, nil
	}

	// The blob grew: append it past the end of the token and repoint the
	// TargetInfo varField at it. This is safe because every field in the
	// message is located by its own BufferOffset/Len, not by position.
	patched = append([]byte(nil), challengeToken...)
	newOffset := len(patched)
	patched = append(patched, newTargetInfo...)
	binary.LittleEndian.PutUint16(patched[40:42], uint16(len(newTargetInfo))) //nolint:gosec // AV-pair blobs are far smaller than 64KiB.
	binary.LittleEndian.PutUint16(patched[42:44], uint16(len(newTargetInfo))) //nolint:gosec // AV-pair blobs are far smaller than 64KiB.
	binary.LittleEndian.PutUint32(patched[44:48], uint32(newOffset))          //nolint:gosec // Message sizes are far smaller than 4GiB.

	return patched, true, nil
}

// ntlmVarFieldOffsetPositions lists, for each of the six varField
// descriptors in the fixed 64-byte AUTHENTICATE_MESSAGE header (MS-NLMP
// §2.2.1.3, and see Azure/go-ntlmssp's authenticateMessageFields), the byte
// position of its 2-byte Len/MaxLen subfield and the byte position of its
// 4-byte BufferOffset subfield.
var ntlmVarFieldOffsetPositions = [6]struct {
	lenPos, offsetPos int
}{
	{12, 16}, // LmChallengeResponse
	{20, 24}, // NtChallengeResponse
	{28, 32}, // DomainName
	{36, 40}, // UserName
	{44, 48}, // Workstation
	{52, 56}, // SessionKey
}

// ntlmAttachMIC computes the MIC over the NEGOTIATE, CHALLENGE, and
// AUTHENTICATE messages (MS-NLMP §3.1.5.1.2) and splices it into a copy of
// authenticateToken. challengeToken must be the original, unpatched
// CHALLENGE_MESSAGE bytes as received from the server (not the locally
// patched copy passed to ntlmssp.NewAuthenticateMessage): the MIC covers
// what was actually exchanged on the wire.
func ntlmAttachMIC(negotiateToken, challengeToken, authenticateToken, exportedSessionKey []byte) ([]byte, error) {
	if len(authenticateToken) < 64 {
		return nil, fmt.Errorf("ntlmssp: AUTHENTICATE token too short to contain a fixed header: %d bytes", len(authenticateToken))
	}
	if flags := binary.LittleEndian.Uint32(authenticateToken[60:64]); flags&ntlmNegotiateVersion != 0 {
		return nil, fmt.Errorf("ntlmssp: AUTHENTICATE_MESSAGE negotiates NTLMSSP_NEGOTIATE_VERSION; MIC header offsets do not support a Version block")
	}

	withMIC := make([]byte, 0, len(authenticateToken)+16)
	withMIC = append(withMIC, authenticateToken[:64]...)
	withMIC = append(withMIC, make([]byte, 16)...)
	withMIC = append(withMIC, authenticateToken[64:]...)

	for _, pos := range ntlmVarFieldOffsetPositions {
		fieldLen := binary.LittleEndian.Uint16(withMIC[pos.lenPos : pos.lenPos+2])
		if fieldLen == 0 {
			continue
		}
		bufferOffset := binary.LittleEndian.Uint32(withMIC[pos.offsetPos : pos.offsetPos+4])
		binary.LittleEndian.PutUint32(withMIC[pos.offsetPos:pos.offsetPos+4], bufferOffset+16)
	}

	mic := ntlmHmacMd5(exportedSessionKey, negotiateToken, challengeToken, withMIC)
	copy(withMIC[64:80], mic)

	return withMIC, nil
}
