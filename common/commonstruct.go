package common


import (
        
        "crypto/elliptic"       
        "math/big"   
        "time"
        "net"
        "encoding/asn1"		
		"crypto/x509/pkix"

)


type CommonPublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type CommonPrivateKey struct {
	CommonPublicKey
	D *big.Int
}
type CommonCertPool struct {
	BySubjectKeyId map[string][]int
	ByName         map[string][]int
	Certs          []*CommonCertificate
}
type CommonPrivKeySm2 [32]byte
// A Certificate represents an X.509 certificate.
type KeyUsage int
type CommonSignatureAlgorithm int
type PublicKeyAlgorithm int
type ExtKeyUsage int
type CommonCertificate struct {
	Raw                     []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
	RawTBSCertificate       []byte // Certificate part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject              []byte // DER encoded Subject
	RawIssuer               []byte // DER encoded Issuer
	Signature          []byte
	CommonSignatureAlgorithm CommonSignatureAlgorithm
	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}
	Version             int
	SerialNumber        *big.Int
	Issuer              pkix.Name
	Subject             pkix.Name
	NotBefore, NotAfter time.Time // Validity bounds.
	KeyUsage            KeyUsage
	Extensions []pkix.Extension
	ExtraExtensions []pkix.Extension
	UnhandledCriticalExtensions []asn1.ObjectIdentifier
	ExtKeyUsage        []ExtKeyUsage           // Sequence of extended key usages.
	UnknownExtKeyUsage []asn1.ObjectIdentifier // Encountered extended key usages unknown to this package.
	BasicConstraintsValid bool // if true then the next two fields are valid.
	IsCA                  bool
	MaxPathLen            int
	MaxPathLenZero bool
	SubjectKeyId   []byte
	AuthorityKeyId []byte
	OCSPServer            []string
	IssuingCertificateURL []string
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	PermittedDNSDomainsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string
	CRLDistributionPoints []string
	PolicyIdentifiers []asn1.ObjectIdentifier
}
type CommonCertificateRequest struct {
	Raw           []byte
	RawTBSCertificateRequest []byte
	RawSubjectPublicKeyInfo  []byte
	RawSubject               []byte
	Version                  int
	Signature                []byte
	CommonSignatureAlgorithm       CommonSignatureAlgorithm
	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}
	Subject            pkix.Name
	Attributes         []pkix.AttributeTypeAndValueSET
	Extensions         []pkix.Extension
	ExtraExtensions    []pkix.Extension
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
}