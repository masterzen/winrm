package winrm

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	. "gopkg.in/check.v1"
)

var rsaByteSizes = []int{512, 1024, 2048, 4096}

func (s *WinRMSuite) TestNewCertRSASize(c *C) {
	for _, size := range rsaByteSizes {
		config := CertConfig{
			Subject:   pkix.Name{CommonName: "winrm client cert"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 24 * time.Hour,
			SizeT:     size,
			Method:    RSA,
		}
		certPem, privPem, err := NewCert(config)
		c.Assert(err, IsNil)
		c.Assert(certPem, Not(IsNil))
		c.Assert(privPem, Not(IsNil))
		caCert, caKey, err := parseCertAndKeyRSA(certPem, privPem)
		c.Assert(err, IsNil)
		c.Check(caCert.Subject.CommonName, Equals, "winrm client cert")
		c.Check(caKey, FitsTypeOf, (*rsa.PrivateKey)(nil))
		c.Check(caCert.Version, Equals, 3)
		value, err := getUPNExtensionValue(config.Subject)
		c.Assert(err, IsNil)
		c.Assert(value, Not(IsNil))
		expected := []pkix.Extension{
			{
				Id:       subjAltName,
				Value:    value,
				Critical: false,
			},
		}
		c.Assert(caCert.Extensions[2], DeepEquals, expected[0])
		c.Assert(caCert.PublicKeyAlgorithm, Equals, x509.RSA)
		c.Assert(caCert.ExtKeyUsage[0], Equals, x509.ExtKeyUsageClientAuth)

	}
}

var formats = []int{P224, P256, P384, P521}

func (s *WinRMSuite) TestNewCertECDSATypes(c *C) {
	for _, f := range formats {
		config := CertConfig{
			Subject:   pkix.Name{CommonName: "winrm client cert"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 24 * time.Hour,
			Method:    ECDSA,
			SizeT:     f,
		}
		certPem, privPem, err := NewCert(config)
		c.Assert(err, IsNil)

		caCert, caKey, err := parseCertAndKeyECDSA(certPem, privPem)
		c.Assert(err, IsNil)
		c.Assert(certPem, Not(IsNil))
		c.Assert(privPem, Not(IsNil))
		c.Check(caCert.Subject.CommonName, Equals, "winrm client cert")
		c.Check(caKey, FitsTypeOf, (*ecdsa.PrivateKey)(nil))
		c.Check(caCert.Version, Equals, 3)
		value, err := getUPNExtensionValue(config.Subject)
		c.Assert(err, IsNil)
		c.Assert(value, Not(IsNil))
		expected := []pkix.Extension{
			{
				Id:       subjAltName,
				Value:    value,
				Critical: false,
			},
		}
		c.Assert(caCert.Extensions[2], DeepEquals, expected[0])
		c.Assert(caCert.PublicKeyAlgorithm, Equals, x509.ECDSA)
		c.Assert(caCert.ExtKeyUsage[0], Equals, x509.ExtKeyUsageClientAuth)
	}
}

// ParseCertAndKey parses the given PEM-formatted X509 certificate
// and RSA private key.
func parseCertAndKeyRSA(certPEM, keyPEM string) (*x509.Certificate, *rsa.PrivateKey, error) {
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	key, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key with unexpected type %T", key)
	}
	return cert, key, nil
}

// ParseCertAndKey parses the given PEM-formatted X509 certificate
// and ECSA private key.
func parseCertAndKeyECDSA(certPEM, keyPEM string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	key, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key with unexpected type %T", key)
	}
	return cert, key, nil
}
