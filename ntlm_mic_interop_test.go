package winrm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	ntlmssp "github.com/Azure/go-ntlmssp"
	. "gopkg.in/check.v1"
)

// ntlmMicFixtureUsername and ntlmMicFixturePassword must stay in sync,
// byte for byte, with friendMicUsername/friendMicPassword in
// scripts/ntlm-bodgit-fixtures/friend_mic_test.go.tmpl. That glue file
// cannot import this package (it is compiled standalone inside a fetched
// copy of bodgit/ntlmssp, in a different module), so the literals are
// duplicated by hand, the same way friend_test.go.tmpl and this package
// already duplicate other fixed fixture values without a shared import.
const (
	ntlmMicFixtureUsername = "mic-fixture-user"
	ntlmMicFixturePassword = "mic-fixture-pass"
)

// TestNtlmMicBodgitInteropFixtures checks that ntlmPatchChallengeForMIC, fed
// into ntlmssp.NewAuthenticateMessage, derives the same NtChallengeResponse
// the real bodgit/ntlmssp source derives from the identical CHALLENGE and
// ClientChallenge. See ntlm_mic_interop_fixtures_test.go's package doc
// comment for what this does and does not prove, and why only
// NtChallengeResponse is compared.
func (s *WinRMSuite) TestNtlmMicBodgitInteropFixtures(c *C) {
	for _, fixture := range ntlmMicBodgitInteropFixtures {
		patchedChallenge, micRequired, err := ntlmPatchChallengeForMIC(fixture.challengeToken)
		c.Assert(err, IsNil, Commentf("fixture %q: ntlmPatchChallengeForMIC", fixture.name))
		c.Assert(micRequired, Equals, true, Commentf("fixture %q: expected MIC to be required", fixture.name))

		origReader := rand.Reader
		rand.Reader = bytes.NewReader(fixture.clientChallenge)
		var exportedSessionKey []byte
		authenticateToken, err := ntlmssp.NewAuthenticateMessage(patchedChallenge, ntlmMicFixtureUsername, ntlmMicFixturePassword, &ntlmssp.AuthenticateMessageOptions{
			ExportedSessionKey: &exportedSessionKey,
		})
		rand.Reader = origReader
		c.Assert(err, IsNil, Commentf("fixture %q: NewAuthenticateMessage", fixture.name))

		ntPos := ntlmVarFieldOffsetPositions[1] // NtChallengeResponse
		c.Assert(len(authenticateToken) >= ntPos.offsetPos+4, Equals, true, Commentf("fixture %q: authenticate token too short", fixture.name))

		length := int(binary.LittleEndian.Uint16(authenticateToken[ntPos.lenPos : ntPos.lenPos+2]))
		offset := int(binary.LittleEndian.Uint32(authenticateToken[ntPos.offsetPos : ntPos.offsetPos+4]))
		c.Assert(offset+length <= len(authenticateToken), Equals, true, Commentf("fixture %q: NtChallengeResponse field out of bounds", fixture.name))
		gotNtChallengeResponse := authenticateToken[offset : offset+length]

		c.Assert(gotNtChallengeResponse, DeepEquals, fixture.ntChallengeResponse, Commentf("fixture %q: NtChallengeResponse mismatch vs real bodgit output", fixture.name))
	}
}
