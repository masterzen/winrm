package winrm

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"time"
)

// credsspMessageProtector implements messageProtector for CredSSP's
// post-handshake traffic. This is plain TLS application data, not NTLM
// sealing (NTLM sealing is used only for the pubKeyAuth step in
// performCredSSPAuth).
type credsspMessageProtector struct {
	tlsConn *tls.Conn
	conn    *credSSPMemoryConn
	timeout time.Duration
}

// Wrap seals message by writing it to tlsConn and reading back the sealed
// TLS record bytes from conn. The result is prefixed with a 4-byte
// little-endian trailer length (MS-CSSP). Same logic as Merge #188's
// buildCredSSPMessage (encryption.go), moved here.
func (p *credsspMessageProtector) Wrap(message []byte) ([]byte, error) {
	if p.tlsConn == nil || p.conn == nil {
		return nil, errors.New("credssp tls context not initialized")
	}

	if _, err := p.tlsConn.Write(message); err != nil {
		return nil, err
	}
	sealedFirst, err := p.conn.popOutgoing(credSSPTimeout(p.timeout))
	if err != nil {
		return nil, err
	}
	sealedMessage := p.conn.drainOutgoing(sealedFirst)

	cipherSuite := tls.CipherSuiteName(p.tlsConn.ConnectionState().CipherSuite)
	trailerLength := getCredSSPTrailerLength(len(message), cipherSuite)

	trailer := make([]byte, 4)
	binary.LittleEndian.PutUint32(trailer, uint32(trailerLength)) //nolint:gosec // trailer length is bounded by a single TLS record's block/hash overhead.

	return append(trailer, sealedMessage...), nil
}

// Unwrap reverses Wrap: it strips the trailer-length prefix, feeds the
// sealed bytes to conn, and reads expectedLength plaintext bytes back from
// tlsConn. A message can span more than one TLS record, so the caller must
// pass the real expected length. Same logic as Merge 3's
// decryptCredsspMessage, moved here.
func (p *credsspMessageProtector) Unwrap(encryptedData []byte, expectedLength int) ([]byte, error) {
	if p.tlsConn == nil || p.conn == nil {
		return nil, errors.New("credssp tls context not initialized")
	}
	if len(encryptedData) < 4 {
		return nil, errors.New("credssp encrypted payload too short")
	}

	// Skip the 4-byte CredSSP trailer length prefix and feed the wrapped TLS
	// record(s) into the tunnel.
	sealed := encryptedData[4:]
	if err := p.conn.pushIncoming(sealed); err != nil {
		return nil, err
	}

	_ = p.tlsConn.SetReadDeadline(time.Now().Add(credSSPTimeout(p.timeout)))
	defer p.tlsConn.SetReadDeadline(time.Time{})

	// The plaintext length is authoritatively given by the MIME
	// OriginalContent header (passed through by message_encryption.go's
	// decrypt()). A single Read returns at most one TLS record's plaintext,
	// so read the full declared length across however many records it
	// spans.
	message := make([]byte, expectedLength)
	if _, err := io.ReadFull(p.tlsConn, message); err != nil {
		return nil, err
	}

	return message, nil
}

// getCredSSPTrailerLength computes the MS-CSSP trailer length (MAC/tag plus
// any block-cipher padding) for a message of messageLength bytes under the
// given TLS cipher suite name.
func getCredSSPTrailerLength(messageLength int, cipherSuite string) int {
	var trailerLength int

	if strings.Contains(cipherSuite, "_GCM_") || strings.Contains(cipherSuite, "-GCM-") {
		trailerLength = 16
	} else if strings.Contains(cipherSuite, "CHACHA20") {
		// ChaCha20-Poly1305 is an AEAD cipher with a 16-byte Poly1305 tag
		// and no block padding, like AES-GCM.
		trailerLength = 16
	} else {
		hashAlgorithm := ""
		if strings.Contains(cipherSuite, "_") {
			hashAlgorithm = cipherSuite[strings.LastIndex(cipherSuite, "_")+1:]
		} else if strings.Contains(cipherSuite, "-") {
			hashAlgorithm = cipherSuite[strings.LastIndex(cipherSuite, "-")+1:]
		}

		var hashLength int
		switch hashAlgorithm {
		case "MD5":
			hashLength = 16
		case "SHA":
			hashLength = 20
		case "SHA256":
			hashLength = 32
		case "SHA384":
			hashLength = 48
		default:
			hashLength = 0
		}

		prePadLength := messageLength + hashLength
		paddingLength := 0

		if strings.Contains(cipherSuite, "RC4") || strings.Contains(cipherSuite, "CHACHA20") {
			paddingLength = 0
		} else if strings.Contains(cipherSuite, "3DES") || strings.Contains(cipherSuite, "DES") {
			paddingLength = 8 - (prePadLength % 8)
			if paddingLength == 8 {
				paddingLength = 0
			}
		} else {
			// AES is a 128 bit block cipher.
			paddingLength = 16 - (prePadLength % 16)
			if paddingLength == 16 {
				paddingLength = 0
			}
		}

		trailerLength = (prePadLength + paddingLength) - messageLength
	}
	return trailerLength
}
