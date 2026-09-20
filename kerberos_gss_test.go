package winrm

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestKerberosContextAcceptsMutualAuthenticationReply(t *testing.T) {
	sessionKey := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: []byte("0123456789abcdef0123456789abcdef"),
	}
	acceptorSubkey := types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: []byte("fedcba9876543210"),
	}
	clientTime := time.Date(2026, time.August, 21, 12, 34, 56, 0, time.UTC)
	context := &kerberosInitiatorContext{
		sessionKey: sessionKey,
		contextKey: sessionKey,
		clientTime: clientTime,
		clientUsec: 123456,
		sendSeq:    9,
	}

	token := testKerberosAPReplyToken(t, sessionKey, messages.EncAPRepPart{
		CTime:          clientTime,
		Cusec:          context.clientUsec,
		Subkey:         acceptorSubkey,
		SequenceNumber: 71,
	})
	if err := context.accept(token); err != nil {
		t.Fatal(err)
	}
	if !context.established || !context.useSubkey || context.receiveSeq != 71 {
		t.Fatalf("established=%t subkey=%t receive sequence=%d", context.established, context.useSubkey, context.receiveSeq)
	}
	if context.contextKey.KeyType != acceptorSubkey.KeyType || string(context.contextKey.KeyValue) != string(acceptorSubkey.KeyValue) {
		t.Fatalf("context key=%v, want acceptor subkey=%v", context.contextKey, acceptorSubkey)
	}
}

func testKerberosAPReplyToken(t *testing.T, sessionKey types.EncryptionKey, reply messages.EncAPRepPart) []byte {
	t.Helper()
	replyBytes, err := asn1.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	replyBytes = asn1tools.AddASNAppTag(replyBytes, asnAppTag.EncAPRepPart)
	encryptedReply, err := crypto.GetEncryptedData(replyBytes, sessionKey, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		t.Fatal(err)
	}
	apReplyBytes, err := asn1.Marshal(messages.APRep{
		PVNO:    5,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: encryptedReply,
	})
	if err != nil {
		t.Fatal(err)
	}
	apReplyBytes = asn1tools.AddASNAppTag(apReplyBytes, asnAppTag.APREP)

	kerberosOID, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		t.Fatal(err)
	}
	mechanismToken := asn1tools.AddASNAppTag(append(append(kerberosOID, 0x02, 0x00), apReplyBytes...), 0)
	response := spnego.NegTokenResp{
		NegState:      asn1.Enumerated(spnego.NegStateAcceptCompleted),
		SupportedMech: gssapi.OIDKRB5.OID(),
		ResponseToken: mechanismToken,
	}
	token, err := response.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestKerberosDCEWrapRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		keyType int32
		key     []byte
	}{
		{name: "aes128-sha1", keyType: etypeID.AES128_CTS_HMAC_SHA1_96, key: []byte("0123456789abcdef")},
		{name: "aes256-sha1", keyType: etypeID.AES256_CTS_HMAC_SHA1_96, key: []byte("0123456789abcdef0123456789abcdef")},
		{name: "aes128-sha2", keyType: etypeID.AES128_CTS_HMAC_SHA256_128, key: []byte("0123456789abcdef")},
		{name: "aes256-sha2", keyType: etypeID.AES256_CTS_HMAC_SHA384_192, key: []byte("0123456789abcdef0123456789abcdef")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := types.EncryptionKey{KeyType: test.keyType, KeyValue: test.key}
			plaintext := []byte("the WinRM SOAP message")
			const sequence = uint64(42)
			token, rrc, ec, err := sealKerberosWrapToken(plaintext, key, keyusage.GSSAPI_ACCEPTOR_SEAL, kerberosWrapFlagSentByAcceptor, sequence)
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.BigEndian.Uint16(token[6:8]); got != rrc || rrc == 0 {
				t.Fatalf("outer RRC=%d returned RRC=%d", got, rrc)
			}
			wantEC := uint16(0)
			if got := binary.BigEndian.Uint16(token[4:6]); got != wantEC {
				t.Fatalf("outer EC=%d, want %d", got, wantEC)
			}
			if got := uint16(binary.BigEndian.Uint16(token[4:6])); got != ec {
				t.Fatalf("returned EC=%d, outer EC=%d", ec, got)
			}
			wantRRC := uint16(16 + 12)
			switch test.keyType {
			case etypeID.AES128_CTS_HMAC_SHA256_128:
				wantRRC = 16 + 16
			case etypeID.AES256_CTS_HMAC_SHA384_192:
				wantRRC = 16 + 24
			}
			wantRRC += wantEC
			if rrc != wantRRC {
				t.Fatalf("RRC=%d, want %d", rrc, wantRRC)
			}
			decrypted, gotSequence, err := unsealKerberosWrapToken(token, key, keyusage.GSSAPI_ACCEPTOR_SEAL, true)
			if err != nil {
				t.Fatal(err)
			}
			if string(decrypted) != string(plaintext) || gotSequence != sequence {
				t.Fatalf("decrypted=%q sequence=%d", decrypted, gotSequence)
			}
		})
	}
}

func TestKerberosMessageProtectorWinRMFraming(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
	context := &kerberosInitiatorContext{
		contextKey:  key,
		sessionKey:  key,
		sendSeq:     7,
		receiveSeq:  11,
		useSubkey:   true,
		established: true,
	}

	outgoing, err := context.Wrap([]byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	headerLength := int(binary.LittleEndian.Uint32(outgoing[:4]))
	if headerLength <= kerberosWrapHeaderLength || headerLength >= len(outgoing)-4 {
		t.Fatalf("unexpected WinRM signature length %d for %d-byte message", headerLength, len(outgoing))
	}
	if headerLength != 60 {
		t.Fatalf("unexpected AES-SHA1 signature length %d, want 60 (IOV header)", headerLength)
	}
	token := outgoing[4:]
	if got := binary.BigEndian.Uint16(token[4:6]); got != 0 {
		t.Fatalf("unexpected AES-SHA1 EC %d, want 0", got)
	}
	if got := binary.BigEndian.Uint16(token[6:8]); got != 28 {
		t.Fatalf("unexpected AES-SHA1 RRC %d, want 28", got)
	}
	if len(outgoing)-(4+headerLength) != len("request") {
		t.Fatalf("unexpected encrypted data length %d, want %d", len(outgoing)-(4+headerLength), len("request"))
	}
	reconstructed := append(append([]byte(nil), outgoing[4:4+headerLength]...), outgoing[4+headerLength:]...)
	request, sequence, err := unsealKerberosWrapToken(reconstructed, key, keyusage.GSSAPI_INITIATOR_SEAL, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" || sequence != 7 || context.sendSeq != 8 {
		t.Fatalf("request=%q sequence=%d next=%d", request, sequence, context.sendSeq)
	}

	responseToken, _, _, err := sealKerberosWrapToken([]byte("response"), key, keyusage.GSSAPI_ACCEPTOR_SEAL, kerberosWrapFlagSentByAcceptor|kerberosWrapFlagAcceptorSubkey, 11)
	if err != nil {
		t.Fatal(err)
	}
	responseHeaderLength := len(responseToken) - len("response")
	response := make([]byte, 4+len(responseToken))
	binary.LittleEndian.PutUint32(response[:4], uint32(responseHeaderLength)) //nolint:gosec // WinRM length fields are 32-bit and the buffer is bounded by memory.
	copy(response[4:4+responseHeaderLength], responseToken[:responseHeaderLength])
	copy(response[4+responseHeaderLength:], responseToken[responseHeaderLength:])

	plaintext, err := context.Unwrap(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "response" || context.receiveSeq != 12 {
		t.Fatalf("response=%q next=%d", plaintext, context.receiveSeq)
	}
}

func TestKerberosWrapRejectsTamperingAndBadSequence(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	token, _, _, err := sealKerberosWrapToken([]byte("response"), key, keyusage.GSSAPI_ACCEPTOR_SEAL, kerberosWrapFlagSentByAcceptor, 3)
	if err != nil {
		t.Fatal(err)
	}
	token[len(token)-1] ^= 0xff
	if _, _, err := unsealKerberosWrapToken(token, key, keyusage.GSSAPI_ACCEPTOR_SEAL, true); err == nil {
		t.Fatal("tampered token was accepted")
	}

	valid, rrc, ec, err := sealKerberosWrapToken([]byte("response"), key, keyusage.GSSAPI_ACCEPTOR_SEAL, kerberosWrapFlagSentByAcceptor, 3)
	if err != nil {
		t.Fatal(err)
	}
	headerLength := kerberosWrapHeaderLength + int(rrc) + int(ec)
	framed := make([]byte, 4+len(valid))
	binary.LittleEndian.PutUint32(framed[:4], uint32(headerLength)) //nolint:gosec // WinRM length fields are 32-bit and the buffer is bounded by memory.
	copy(framed[4:4+headerLength], valid[:headerLength])
	copy(framed[4+headerLength:], valid[headerLength:])
	context := &kerberosInitiatorContext{contextKey: key, receiveSeq: 4, established: true}
	if _, err := context.Unwrap(framed); err == nil || !strings.Contains(err.Error(), "sequence mismatch") {
		t.Fatalf("unexpected sequence error: %v", err)
	}
}

func TestKerberosRC4WinRMWrapRoundTrip(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.RC4_HMAC, KeyValue: []byte("0123456789abcdef")}
	context := &kerberosInitiatorContext{
		contextKey:  key,
		sessionKey:  key,
		sendSeq:     18,
		receiveSeq:  19,
		established: true,
	}
	contextMessage, err := context.Wrap([]byte("legacy context request"))
	if err != nil {
		t.Fatal(err)
	}
	// The test server response uses the next sequence number and the acceptor
	// direction, exercising the RC4 branch selected by key type.
	contextResponse, err := wrapKerberosRC4Message([]byte("legacy context response"), key, 19, true)
	if err != nil {
		t.Fatal(err)
	}
	contextPlaintext, err := context.Unwrap(contextResponse)
	if err != nil {
		t.Fatal(err)
	}
	if len(contextMessage) == 0 || string(contextPlaintext) != "legacy context response" || context.sendSeq != 19 || context.receiveSeq != 20 {
		t.Fatalf("context request=%d response=%q send=%d receive=%d", len(contextMessage), contextPlaintext, context.sendSeq, context.receiveSeq)
	}

	serverMessage, err := wrapKerberosRC4Message([]byte("legacy response"), key, 19, true)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, sequence, err := unwrapKerberosRC4Message(serverMessage, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "legacy response" || sequence != 19 {
		t.Fatalf("plaintext=%q sequence=%d", plaintext, sequence)
	}

	clientMessage, err := wrapKerberosRC4Message([]byte("legacy request"), key, 20, false)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, sequence, err = unwrapKerberosRC4Message(clientMessage, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "legacy request" || sequence != 20 {
		t.Fatalf("plaintext=%q sequence=%d", plaintext, sequence)
	}

	// RC4-HMAC always adds one padding byte. In particular, an aligned input
	// ending in 0x01 must retain that byte when unwrapped.
	aligned := []byte{'1', '2', '3', '4', '5', '6', '7', 0x01}
	alignedMessage, err := wrapKerberosRC4Message(aligned, key, 21, false)
	if err != nil {
		t.Fatal(err)
	}
	signatureLength := int(binary.LittleEndian.Uint32(alignedMessage[:4]))
	if signatureLength != 45 || len(alignedMessage)-(4+signatureLength) != len(aligned)+1 {
		t.Fatalf("signature=%d encrypted data=%d", signatureLength, len(alignedMessage)-(4+signatureLength))
	}
	plaintext, _, err = unwrapKerberosRC4Message(alignedMessage, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != string(aligned) {
		t.Fatalf("aligned plaintext=%x, want %x", plaintext, aligned)
	}
}

func TestNegotiateResponseToken(t *testing.T) {
	want := []byte{1, 2, 3, 4}
	header := "Kerberos, Negotiate " + base64.StdEncoding.EncodeToString(want)
	got, err := negotiateResponseToken([]string{header})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %x, want %x", got, want)
	}
	if _, err := negotiateResponseToken([]string{"Negotiate !!!"}); err == nil {
		t.Fatal("invalid base64 token was accepted")
	}
	got, err = negotiateResponseToken([]string{"Kerberos " + base64.StdEncoding.EncodeToString(want)})
	if err != nil || string(got) != string(want) {
		t.Fatalf("Kerberos scheme: got %x, error %v", got, err)
	}
}
