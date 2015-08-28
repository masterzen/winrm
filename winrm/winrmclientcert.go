package winrm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type EcdsaCurve string

var (
	None EcdsaCurve = ""
	P224 EcdsaCurve = "P224"
	P256 EcdsaCurve = "P256"
	P384 EcdsaCurve = "P384"
	P521 EcdsaCurve = "P521"
)

type WinrmClientCert struct {
	Subject    pkix.Name
	ValidFrom  time.Time
	ValidFor   time.Duration
	RsaBits    int
	EcdsaCurve EcdsaCurve
	Priv       interface{}
	Cert       []byte
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

type KeyPurposeId struct {
	OID asn1.ObjectIdentifier
}

type OtherName struct {
	A string `asn1:"utf8"`
}

type GeneralName struct {
	OID       asn1.ObjectIdentifier
	OtherName `asn1:"tag:0"`
}

type GeneralNames struct {
	GeneralName `asn1:"tag:0"`
}

func NewWinrmClientCertificate(subject pkix.Name, validFrom time.Time, validFor time.Duration, rsaBits int, ecdsaCurve EcdsaCurve) (s *WinrmClientCert, err error) {
	var priv interface{}

	switch ecdsaCurve {
	case None:
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	case P224:
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case P256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case P384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case P521:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, fmt.Errorf("Unrecognized elliptic curve: %q", ecdsaCurve)
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to generate private key: %s", err)
	}

	notBefore := validFrom
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate serial number: %s", err)
	}

	oidOtherName := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	commonName := OtherName{subject.CommonName}

	sequence := GeneralName{
		OID:       oidOtherName,
		OtherName: commonName,
	}

	val, err := asn1.Marshal(GeneralNames{sequence})

	if err != nil {
		return nil, fmt.Errorf("Failed to marshal value: %s", err)
	}

	template := x509.Certificate{
		Subject:            subject,
		SerialNumber:       serialNumber,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: x509.SHA1WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
				Critical: false,
				Value:    val,
			},
		},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %s", err)
	}

	s = &WinrmClientCert{
		Subject:    subject,
		ValidFrom:  validFrom,
		ValidFor:   validFor,
		RsaBits:    rsaBits,
		EcdsaCurve: ecdsaCurve,
		Priv:       priv,
		Cert:       cert,
	}

	return s, nil
}

func (s *WinrmClientCert) ExportPem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Cert})
}

func (s *WinrmClientCert) ExportKey() []byte {
	return pem.EncodeToMemory(pemBlockForKey(s.Priv))
}
