package winrm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- mandated by the Kerberos RC4-HMAC profile (RFC 4757).
	"crypto/rand"
	"crypto/rc4" //nolint:gosec // required for interoperability with legacy Kerberos RC4-HMAC.
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	kerberosWrapHeaderLength = 16

	kerberosWrapFlagSentByAcceptor = byte(0x01)
	kerberosWrapFlagSealed         = byte(0x02)
	kerberosWrapFlagAcceptorSubkey = byte(0x04)

	kerberosContextFlags = gssapi.ContextFlagMutual |
		gssapi.ContextFlagReplay |
		gssapi.ContextFlagSequence |
		gssapi.ContextFlagConf |
		gssapi.ContextFlagInteg
)

var kerberosWrapTokenID = []byte{0x05, 0x04}

var kerberosRC4GSSHeader = []byte{0x60, 0x2b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

// kerberosInitiatorContext is the client side of an RFC 4121 security
// context. It retains the service ticket key, verifies mutual authentication,
// and owns the independent send/receive sequence spaces used by GSS Wrap.
type kerberosInitiatorContext struct {
	mu sync.Mutex

	sessionKey types.EncryptionKey
	contextKey types.EncryptionKey

	clientTime  time.Time
	clientUsec  int
	sendSeq     uint64
	receiveSeq  uint64
	useSubkey   bool
	established bool
}

func newKerberosInitiatorContext(kerberosClient *client.Client, spn string) (*kerberosInitiatorContext, []byte, error) {
	if kerberosClient == nil {
		return nil, nil, errors.New("kerberos client is nil")
	}
	if spn == "" {
		return nil, nil, errors.New("kerberos SPN is empty")
	}
	if err := kerberosClient.AffirmLogin(); err != nil {
		return nil, nil, fmt.Errorf("kerberos login: %w", err)
	}
	ticket, sessionKey, err := kerberosClient.GetServiceTicket(spn)
	if err != nil {
		return nil, nil, fmt.Errorf("get Kerberos service ticket for %q: %w", spn, err)
	}
	if err := validateKerberosMessageEncryptionEType(sessionKey.KeyType); err != nil {
		return nil, nil, err
	}

	authenticator, err := types.NewAuthenticator(kerberosClient.Credentials.Domain(), kerberosClient.Credentials.CName())
	if err != nil {
		return nil, nil, fmt.Errorf("create Kerberos authenticator: %w", err)
	}
	// Older MIT and Windows implementations treat the sequence as signed.
	authenticator.SeqNumber &= 0x3fffffff
	authenticator.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  kerberosAuthenticatorChecksum(kerberosContextFlags),
	}

	apRequest, err := messages.NewAPReq(ticket, sessionKey, authenticator)
	if err != nil {
		return nil, nil, fmt.Errorf("create Kerberos AP-REQ: %w", err)
	}
	types.SetFlag(&apRequest.APOptions, flags.APOptionMutualRequired)

	mechanismToken, err := marshalKerberosAPRequest(apRequest)
	if err != nil {
		return nil, nil, err
	}
	negotiationToken, err := marshalSPNEGOKerberosInit(mechanismToken)
	if err != nil {
		return nil, nil, err
	}

	context := &kerberosInitiatorContext{
		sessionKey: sessionKey,
		contextKey: sessionKey,
		clientTime: authenticator.CTime,
		clientUsec: authenticator.Cusec,
		sendSeq:    uint64(authenticator.SeqNumber), //nolint:gosec // Kerberos sequence numbers are non-negative protocol values.
	}
	return context, negotiationToken, nil
}

func kerberosAuthenticatorChecksum(contextFlags int) []byte {
	checksum := make([]byte, 24)
	// RFC 4121 section 4.1.1: the channel-binding field is always 16 bytes.
	binary.LittleEndian.PutUint32(checksum[:4], 16)
	binary.LittleEndian.PutUint32(checksum[20:24], uint32(contextFlags)) //nolint:gosec // context flags fit the 32-bit GSS field.
	return checksum
}

func marshalKerberosAPRequest(request messages.APReq) ([]byte, error) {
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, fmt.Errorf("marshal Kerberos OID: %w", err)
	}
	apRequest, err := request.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal Kerberos AP-REQ: %w", err)
	}
	mechanismToken := append(append(oid, 0x01, 0x00), apRequest...)
	return asn1tools.AddASNAppTag(mechanismToken, 0), nil
}

func marshalSPNEGOKerberosInit(mechanismToken []byte) ([]byte, error) {
	init := spnego.NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		MechTokenBytes: mechanismToken,
	}
	initBytes, err := init.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal SPNEGO NegTokenInit: %w", err)
	}
	oid, err := asn1.Marshal(gssapi.OIDSPNEGO.OID())
	if err != nil {
		return nil, fmt.Errorf("marshal SPNEGO OID: %w", err)
	}
	return asn1tools.AddASNAppTag(append(oid, initBytes...), 0), nil
}

func (c *kerberosInitiatorContext) accept(token []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.established {
		return errors.New("kerberos security context is already established")
	}
	mechanismToken, err := kerberosResponseMechanismToken(token)
	if err != nil {
		return err
	}
	var krbToken spnego.KRB5Token
	if err := krbToken.Unmarshal(mechanismToken); err != nil {
		return fmt.Errorf("parse Kerberos AP-REP token: %w", err)
	}
	if !krbToken.IsAPRep() {
		return errors.New("kerberos mutual-authentication response does not contain AP-REP")
	}

	decrypted, err := crypto.DecryptEncPart(krbToken.APRep.EncPart, c.sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return fmt.Errorf("decrypt Kerberos AP-REP: %w", err)
	}
	var reply messages.EncAPRepPart
	if err := reply.Unmarshal(decrypted); err != nil {
		return fmt.Errorf("parse Kerberos AP-REP encrypted part: %w", err)
	}
	if reply.CTime.Unix() != c.clientTime.Unix() || reply.Cusec != c.clientUsec {
		return errors.New("kerberos mutual authentication failed: AP-REP timestamp does not match AP-REQ")
	}
	if reply.Subkey.KeyType != 0 {
		if err := validateKerberosMessageEncryptionEType(reply.Subkey.KeyType); err != nil {
			return fmt.Errorf("kerberos acceptor subkey: %w", err)
		}
		c.contextKey = reply.Subkey
		c.useSubkey = true
	}
	c.receiveSeq = uint64(reply.SequenceNumber) //nolint:gosec // Kerberos sequence numbers are non-negative protocol values.
	c.established = true
	return nil
}

func kerberosResponseMechanismToken(token []byte) ([]byte, error) {
	if len(token) == 0 {
		return nil, errors.New("kerberos mutual-authentication response token is empty")
	}
	// SPNEGO NegTokenResp is context-specific tag 1 (0xa1). A server can also
	// return the raw Kerberos GSS mechanism token.
	if token[0] != 0xa1 {
		return token, nil
	}
	var response spnego.SPNEGOToken
	if err := response.Unmarshal(token); err != nil {
		return nil, fmt.Errorf("parse SPNEGO response: %w", err)
	}
	if !response.Resp || len(response.NegTokenResp.ResponseToken) == 0 {
		return nil, errors.New("spnego response does not contain a Kerberos response token")
	}
	return response.NegTokenResp.ResponseToken, nil
}

func validateKerberosMessageEncryptionEType(keyType int32) error {
	// RC4-HMAC is retained solely for interoperability with Kerberos peers
	// that negotiate the legacy RFC 4757 enctype. It is never selected for an
	// AES session; callers should prefer AES enctypes whenever the KDC offers
	// them.
	switch keyType {
	case etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA256_128,
		etypeID.AES256_CTS_HMAC_SHA384_192,
		etypeID.RC4_HMAC:
		return nil
	case etypeID.RC4_HMAC_EXP:
		return fmt.Errorf("export-strength Kerberos RC4 enctype %d is not supported for WinRM message encryption", keyType)
	default:
		return fmt.Errorf("kerberos enctype %d is not supported for WinRM message encryption", keyType)
	}
}

func (c *kerberosInitiatorContext) Wrap(message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.established {
		return nil, errors.New("kerberos security context is not established")
	}

	if c.contextKey.KeyType == etypeID.RC4_HMAC {
		result, err := wrapKerberosRC4Message(message, c.contextKey, c.sendSeq, false)
		if err != nil {
			return nil, err
		}
		c.sendSeq++
		return result, nil
	}

	flags := kerberosWrapFlagSealed
	if c.useSubkey {
		flags |= kerberosWrapFlagAcceptorSubkey
	}
	token, _, _, err := sealKerberosWrapToken(message, c.contextKey, keyusage.GSSAPI_INITIATOR_SEAL, flags, c.sendSeq)
	if err != nil {
		return nil, err
	}
	// The DCE/IOV header buffer contains the clear GSS header, the encrypted
	// copy of that header, the checksum, and the encrypted confounder. The
	// payload is a separate encrypted data buffer after the RRC rotation.
	signatureLength := len(token) - len(message)
	if signatureLength > len(token) {
		return nil, fmt.Errorf("kerberos wrap token signature length %d exceeds token length %d", signatureLength, len(token))
	}

	result := make([]byte, 4+len(token))
	binary.LittleEndian.PutUint32(result[:4], uint32(signatureLength)) //nolint:gosec // WinRM length fields are 32-bit and the buffer is bounded by memory.
	copy(result[4:4+signatureLength], token[:signatureLength])
	copy(result[4+signatureLength:], token[signatureLength:])
	c.sendSeq++
	return result, nil
}

func (c *kerberosInitiatorContext) Unwrap(message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.established {
		return nil, errors.New("kerberos security context is not established")
	}
	if c.contextKey.KeyType == etypeID.RC4_HMAC {
		plaintext, sequence, err := unwrapKerberosRC4Message(message, c.contextKey, true)
		if err != nil {
			return nil, err
		}
		if sequence != c.receiveSeq {
			return nil, fmt.Errorf("kerberos response sequence mismatch: expected %d, got %d", c.receiveSeq, sequence)
		}
		c.receiveSeq++
		return plaintext, nil
	}

	if len(message) < 4 {
		return nil, errors.New("kerberos encrypted payload is shorter than its length prefix")
	}
	signatureLength := int(binary.LittleEndian.Uint32(message[:4]))
	if signatureLength < kerberosWrapHeaderLength || signatureLength > len(message)-4 {
		return nil, fmt.Errorf("invalid Kerberos signature length %d for payload of %d bytes", signatureLength, len(message))
	}
	// WinRM splits the DCE-style GSS token into a signature and data buffer.
	// Joining the buffers restores the complete token before undoing the
	// rotation.
	token := append(append([]byte(nil), message[4:4+signatureLength]...), message[4+signatureLength:]...)
	plaintext, sequence, err := unsealKerberosWrapToken(token, c.contextKey, keyusage.GSSAPI_ACCEPTOR_SEAL, true)
	if err != nil {
		return nil, err
	}
	if sequence != c.receiveSeq {
		return nil, fmt.Errorf("kerberos response sequence mismatch: expected %d, got %d", c.receiveSeq, sequence)
	}
	c.receiveSeq++
	return plaintext, nil
}

func sealKerberosWrapToken(payload []byte, key types.EncryptionKey, usage uint32, flags byte, sequence uint64) ([]byte, uint16, uint16, error) {
	if key.KeyType == etypeID.RC4_HMAC {
		return nil, 0, 0, errors.New("rc4-HMAC uses RFC 1964 wrap tokens, not RFC 4121 CFX tokens")
	}
	if err := validateKerberosMessageEncryptionEType(key.KeyType); err != nil {
		return nil, 0, 0, err
	}
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("get Kerberos encryption type: %w", err)
	}
	flags |= kerberosWrapFlagSealed
	// Windows' WinRM GSS IOV path uses EC=0 and RRC=confounder+checksum
	// (28 bytes for AES-SHA1). This is an observed wire-format invariant from
	// live Windows WinRM and a working GSSAPI IOV client. RFC 4121's baseline
	// description and MS-KILE's generic EC guidance are misleading for this
	// WinRM format; do not simplify this back to an EC=16 token.
	ec := uint16(0)
	rrc := uint16(etype.GetConfounderByteSize() + etype.GetHMACBitLength()/8) //nolint:gosec // supported Kerberos etypes have a small fixed RRC.

	header := kerberosWrapHeader(flags, ec, 0, sequence)
	plaintext := make([]byte, 0, len(payload)+len(header))
	plaintext = append(plaintext, payload...)
	plaintext = append(plaintext, header...)
	_, ciphertext, err := etype.EncryptMessage(key.KeyValue, plaintext, usage)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("encrypt Kerberos wrap token: %w", err)
	}
	// MIT's crypto-IOV order is confounder | payload | encrypted header |
	// checksum. Its WinRM buffer placement is obtained by rotating the
	// complete ciphertext right by the encrypted-header-plus-checksum length:
	// clear header | encrypted header | checksum | encrypted confounder |
	// encrypted payload.
	rotateRight(ciphertext, int(rrc))

	token := make([]byte, kerberosWrapHeaderLength+len(ciphertext))
	copy(token[:kerberosWrapHeaderLength], kerberosWrapHeader(flags, ec, rrc, sequence))
	copy(token[kerberosWrapHeaderLength:], ciphertext)
	return token, rrc, ec, nil
}

func unsealKerberosWrapToken(token []byte, key types.EncryptionKey, usage uint32, expectFromAcceptor bool) ([]byte, uint64, error) {
	if key.KeyType == etypeID.RC4_HMAC {
		return nil, 0, errors.New("rc4-HMAC uses RFC 1964 wrap tokens, not RFC 4121 CFX tokens")
	}
	if err := validateKerberosMessageEncryptionEType(key.KeyType); err != nil {
		return nil, 0, err
	}
	if len(token) < kerberosWrapHeaderLength {
		return nil, 0, errors.New("kerberos wrap token is shorter than its header")
	}
	if !bytes.Equal(token[:2], kerberosWrapTokenID) {
		return nil, 0, fmt.Errorf("invalid Kerberos wrap token ID %x", token[:2])
	}
	flags := token[2]
	if token[3] != 0xff {
		return nil, 0, fmt.Errorf("invalid Kerberos wrap token filler 0x%02x", token[3])
	}
	if flags&kerberosWrapFlagSealed == 0 {
		return nil, 0, errors.New("kerberos wrap token is not sealed")
	}
	fromAcceptor := flags&kerberosWrapFlagSentByAcceptor != 0
	if fromAcceptor != expectFromAcceptor {
		return nil, 0, fmt.Errorf("kerberos wrap token direction mismatch: from acceptor is %t", fromAcceptor)
	}
	ec := binary.BigEndian.Uint16(token[4:6])
	rrc := binary.BigEndian.Uint16(token[6:8])
	sequence := binary.BigEndian.Uint64(token[8:16])

	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, 0, fmt.Errorf("get Kerberos encryption type: %w", err)
	}
	wantRRC := uint16(etype.GetConfounderByteSize() + etype.GetHMACBitLength()/8) //nolint:gosec // supported Kerberos etypes have a small fixed RRC.
	if rrc != wantRRC {
		return nil, 0, fmt.Errorf("unexpected Kerberos DCE RRC %d, want %d", rrc, wantRRC)
	}
	minimumCiphertext := etype.GetConfounderByteSize() + etype.GetHMACBitLength()/8 + kerberosWrapHeaderLength + int(ec)
	if len(token)-kerberosWrapHeaderLength < minimumCiphertext {
		return nil, 0, fmt.Errorf("kerberos wrap token ciphertext is too short: got %d, need at least %d", len(token)-kerberosWrapHeaderLength, minimumCiphertext)
	}
	ciphertext := append([]byte(nil), token[kerberosWrapHeaderLength:]...)
	rotateLeft(ciphertext, int(rrc))
	plaintext, err := etype.DecryptMessage(key.KeyValue, ciphertext, usage)
	if err != nil {
		return nil, 0, fmt.Errorf("decrypt Kerberos wrap token: %w", err)
	}
	if len(plaintext) < kerberosWrapHeaderLength+int(ec) {
		return nil, 0, errors.New("decrypted Kerberos wrap token is too short")
	}
	headerOffset := len(plaintext) - kerberosWrapHeaderLength
	expectedHeader := kerberosWrapHeader(flags, ec, 0, sequence)
	if !bytes.Equal(plaintext[headerOffset:], expectedHeader) {
		return nil, 0, errors.New("kerberos wrap token encrypted header does not match its outer header")
	}
	payloadLength := headerOffset - int(ec)
	if payloadLength < 0 {
		return nil, 0, errors.New("kerberos wrap token has an invalid extra count")
	}
	return plaintext[:payloadLength], sequence, nil
}

func kerberosWrapHeader(flags byte, ec, rrc uint16, sequence uint64) []byte {
	header := make([]byte, kerberosWrapHeaderLength)
	copy(header[:2], kerberosWrapTokenID)
	header[2] = flags
	header[3] = 0xff
	binary.BigEndian.PutUint16(header[4:6], ec)
	binary.BigEndian.PutUint16(header[6:8], rrc)
	binary.BigEndian.PutUint64(header[8:16], sequence)
	return header
}

func rotateRight(data []byte, count int) {
	if len(data) == 0 {
		return
	}
	count %= len(data)
	if count == 0 {
		return
	}
	copyData := append([]byte(nil), data...)
	copy(data[:count], copyData[len(copyData)-count:])
	copy(data[count:], copyData[:len(copyData)-count])
}

func rotateLeft(data []byte, count int) {
	if len(data) == 0 {
		return
	}
	count %= len(data)
	if count == 0 {
		return
	}
	copyData := append([]byte(nil), data...)
	copy(data, copyData[count:])
	copy(data[len(data)-count:], copyData[:count])
}

// wrapKerberosRC4Message implements the legacy RC4-HMAC GSS_Wrap profile from
// RFC 4757 section 7.3. RC4 is intentionally confined to this function and is
// reached only when the negotiated Kerberos key is etype RC4-HMAC. Unlike the
// CFX token, its 45-byte GSS/token header is the WinRM signature buffer and
// the encrypted application bytes are separate.
func wrapKerberosRC4Message(payload []byte, key types.EncryptionKey, sequence uint64, fromAcceptor bool) ([]byte, error) {
	if key.KeyType != etypeID.RC4_HMAC || len(key.KeyValue) != 16 {
		return nil, fmt.Errorf("invalid RC4-HMAC Kerberos key type or length")
	}
	if sequence > uint64(^uint32(0)) {
		return nil, fmt.Errorf("rc4-HMAC sequence number %d exceeds 32 bits", sequence)
	}

	// RFC 4757 section 7.3 rounds RC4-HMAC padding to one byte. The byte is
	// mandatory and contains its own length, so its value is always 0x01.
	padded := append(append([]byte(nil), payload...), 0x01)

	token := make([]byte, 32)
	copy(token[:8], []byte{0x02, 0x01, 0x11, 0x00, 0x10, 0x00, 0xff, 0xff})
	sequencePlain := make([]byte, 8)
	binary.BigEndian.PutUint32(sequencePlain[:4], uint32(sequence))
	if fromAcceptor {
		copy(sequencePlain[4:], []byte{0xff, 0xff, 0xff, 0xff})
	}
	confounder := make([]byte, 8)
	if _, err := rand.Read(confounder); err != nil {
		return nil, fmt.Errorf("generate RC4-HMAC confounder: %w", err)
	}

	signingKey := hmacMD5(key.KeyValue, []byte("signaturekey\x00"))
	checksumInput := make([]byte, 4, 4+8+len(confounder)+len(padded))
	binary.LittleEndian.PutUint32(checksumInput, 13)
	checksumInput = append(checksumInput, token[:8]...)
	checksumInput = append(checksumInput, confounder...)
	checksumInput = append(checksumInput, padded...)
	digest := md5.Sum(checksumInput) // #nosec G401 -- mandated by RFC 4757.
	checksum := hmacMD5(signingKey, digest[:])[:8]
	copy(token[16:24], checksum)

	sequenceKey := hmacMD5(hmacMD5(key.KeyValue, []byte{0, 0, 0, 0}), checksum)
	encryptedSequence, err := rc4Crypt(sequenceKey, sequencePlain)
	if err != nil {
		return nil, err
	}
	copy(token[8:16], encryptedSequence)

	localKey := append([]byte(nil), key.KeyValue...)
	for i := range localKey {
		localKey[i] ^= 0xf0
	}
	encryptionKey := hmacMD5(hmacMD5(localKey, []byte{0, 0, 0, 0}), sequencePlain[:4])
	stream, err := rc4.NewCipher(encryptionKey) // #nosec G405 -- mandated by RFC 4757.
	if err != nil {
		return nil, fmt.Errorf("create RC4-HMAC stream: %w", err)
	}
	encryptedConfounder := make([]byte, len(confounder))
	stream.XORKeyStream(encryptedConfounder, confounder)
	encryptedPayload := make([]byte, len(padded))
	stream.XORKeyStream(encryptedPayload, padded)
	copy(token[24:32], encryptedConfounder)

	signature := append(append([]byte(nil), kerberosRC4GSSHeader...), token...)
	result := make([]byte, 4+len(signature)+len(encryptedPayload))
	binary.LittleEndian.PutUint32(result[:4], uint32(len(signature))) //nolint:gosec // WinRM length fields are 32-bit and the buffer is bounded by memory.
	copy(result[4:4+len(signature)], signature)
	copy(result[4+len(signature):], encryptedPayload)
	return result, nil
}

func unwrapKerberosRC4Message(message []byte, key types.EncryptionKey, expectFromAcceptor bool) ([]byte, uint64, error) {
	if key.KeyType != etypeID.RC4_HMAC || len(key.KeyValue) != 16 {
		return nil, 0, fmt.Errorf("invalid RC4-HMAC Kerberos key type or length")
	}
	if len(message) < 4 {
		return nil, 0, errors.New("rc4-HMAC payload is shorter than its length prefix")
	}
	signatureLength := int(binary.LittleEndian.Uint32(message[:4]))
	if signatureLength != len(kerberosRC4GSSHeader)+32 || signatureLength > len(message)-4 {
		return nil, 0, fmt.Errorf("invalid RC4-HMAC signature length %d", signatureLength)
	}
	signature := message[4 : 4+signatureLength]
	if !bytes.Equal(signature[:len(kerberosRC4GSSHeader)], kerberosRC4GSSHeader) {
		return nil, 0, errors.New("invalid RC4-HMAC GSS header")
	}
	token := signature[len(kerberosRC4GSSHeader):]
	if !bytes.Equal(token[:8], []byte{0x02, 0x01, 0x11, 0x00, 0x10, 0x00, 0xff, 0xff}) {
		return nil, 0, errors.New("invalid RC4-HMAC wrap-token header")
	}
	checksum := token[16:24]
	sequenceKey := hmacMD5(hmacMD5(key.KeyValue, []byte{0, 0, 0, 0}), checksum)
	sequencePlain, err := rc4Crypt(sequenceKey, token[8:16])
	if err != nil {
		return nil, 0, err
	}
	expectedDirection := byte(0x00)
	if expectFromAcceptor {
		expectedDirection = 0xff
	}
	for _, direction := range sequencePlain[4:] {
		if direction != expectedDirection {
			return nil, 0, errors.New("rc4-HMAC wrap-token direction mismatch")
		}
	}
	sequence := binary.BigEndian.Uint32(sequencePlain[:4])

	localKey := append([]byte(nil), key.KeyValue...)
	for i := range localKey {
		localKey[i] ^= 0xf0
	}
	encryptionKey := hmacMD5(hmacMD5(localKey, []byte{0, 0, 0, 0}), sequencePlain[:4])
	stream, err := rc4.NewCipher(encryptionKey) // #nosec G405 -- mandated by RFC 4757.
	if err != nil {
		return nil, 0, fmt.Errorf("create RC4-HMAC stream: %w", err)
	}
	confounder := make([]byte, 8)
	stream.XORKeyStream(confounder, token[24:32])
	ciphertext := message[4+signatureLength:]
	padded := make([]byte, len(ciphertext))
	stream.XORKeyStream(padded, ciphertext)

	signingKey := hmacMD5(key.KeyValue, []byte("signaturekey\x00"))
	checksumInput := make([]byte, 4, 4+8+len(confounder)+len(padded))
	binary.LittleEndian.PutUint32(checksumInput, 13)
	checksumInput = append(checksumInput, token[:8]...)
	checksumInput = append(checksumInput, confounder...)
	checksumInput = append(checksumInput, padded...)
	digest := md5.Sum(checksumInput) // #nosec G401 -- mandated by RFC 4757.
	expectedChecksum := hmacMD5(signingKey, digest[:])[:8]
	if !hmac.Equal(checksum, expectedChecksum) {
		return nil, 0, errors.New("rc4-HMAC wrap-token checksum mismatch")
	}

	if len(padded) == 0 || padded[len(padded)-1] != 0x01 {
		return nil, 0, errors.New("invalid RC4-HMAC wrap-token padding")
	}
	return padded[:len(padded)-1], uint64(sequence), nil
}

func hmacMD5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key) // #nosec G401 -- mandated by RFC 4757.
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func rc4Crypt(key, data []byte) ([]byte, error) {
	stream, err := rc4.NewCipher(key) // #nosec G405 -- mandated by RFC 4757.
	if err != nil {
		return nil, fmt.Errorf("create RC4-HMAC stream: %w", err)
	}
	result := make([]byte, len(data))
	stream.XORKeyStream(result, data)
	return result, nil
}
