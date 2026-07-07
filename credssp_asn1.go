package winrm

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

const (
	credSSPMinimumVersion = 2
	credSSPVersion5       = 5
	credSSPDefaultVersion = 6
)

const (
	credSSPAuthTypePassword = 1
)

type negoDataItem struct {
	NegoToken []byte `asn1:"explicit,tag:0"`
}

type tsRequest struct {
	Version     int            `asn1:"explicit,tag:0"`
	NegoTokens  []negoDataItem `asn1:"explicit,optional,tag:1"`
	AuthInfo    []byte         `asn1:"explicit,optional,tag:2"`
	PubKeyAuth  []byte         `asn1:"explicit,optional,tag:3"`
	ErrorCode   int64          `asn1:"explicit,optional,tag:4"`
	ClientNonce []byte         `asn1:"explicit,optional,tag:5"`
}

type tsCredentials struct {
	CredType    int    `asn1:"explicit,tag:0"`
	Credentials []byte `asn1:"explicit,tag:1"`
}

type tspasswordCreds struct {
	DomainName []byte `asn1:"explicit,tag:0"`
	UserName   []byte `asn1:"explicit,tag:1"`
	Password   []byte `asn1:"explicit,tag:2"`
}

func marshalTSRequest(request tsRequest) ([]byte, error) {
	return asn1.Marshal(request)
}

func unmarshalTSRequest(value []byte) (*tsRequest, error) {
	var request tsRequest
	rest, err := asn1.Unmarshal(value, &request)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("unexpected trailing bytes in TSRequest")
	}
	return &request, nil
}

// utf16LEBytes encodes a string as little-endian UTF-16, the encoding Windows
// requires for the OCTET STRING fields of TSPasswordCreds.
func utf16LEBytes(s string) []byte {
	codes := utf16.Encode([]rune(s))
	out := make([]byte, len(codes)*2)
	for i, c := range codes {
		binary.LittleEndian.PutUint16(out[i*2:], c)
	}
	return out
}

func marshalCredentials(domain, user, password string) ([]byte, error) {
	passwordCreds, err := asn1.Marshal(tspasswordCreds{
		DomainName: utf16LEBytes(domain),
		UserName:   utf16LEBytes(user),
		Password:   utf16LEBytes(password),
	})
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(tsCredentials{
		CredType:    credSSPAuthTypePassword,
		Credentials: passwordCreds,
	})
}
