package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"time"
)

// Cert represents a DNSCrypt server certificate.
// For information on creating a certificate, refer to ResolverConfig.
type Cert struct {
	Serial      uint32             // 4-byte serial number in big-endian format.
	EsVersion   CryptoConstruction // Cryptographic construction version.
	Signature   [ed25519.SignatureSize]byte
	ResolverPk  [keySize]byte // Resolver's short-term public key (32 bytes when using X25519).
	ResolverSk  [keySize]byte // Resolver's short-term private key (32 bytes when using X25519).
	ClientMagic [clientMagicSize]byte
	NotBefore   uint32 // Validity start date as a big-endian 4-byte unsigned Unix timestamp.
	NotAfter    uint32 // Validity end date (inclusive) as a big-endian 4-byte unsigned Unix timestamp.
}

// Serialize serializes the certificate to bytes.
// The serialized certificate is 124 bytes long.
func (c *Cert) Serialize() ([]byte, error) {
	// Validate the certificate parameters.
	if c.EsVersion == UndefinedConstruction {
		return nil, ErrEsVersion
	}

	if !c.VerifyDate() {
		return nil, ErrInvalidDate
	}

	// Start serializing.
	b := make([]byte, 124)

	// <cert-magic>
	copy(b[:4], certMagic[:])
	// <es-version>
	binary.BigEndian.PutUint16(b[4:6], uint16(c.EsVersion))
	// <protocol-minor-version> - always 0x00 0x00
	copy(b[6:8], []byte{0, 0})
	// <signature>
	copy(b[8:72], c.Signature[:ed25519.SignatureSize])
	// signed: (<resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>)
	c.writeSigned(b[72:])

	// Done.
	return b, nil
}

// Deserialize deserializes a certificate from a byte array.
func (c *Cert) Deserialize(b []byte) error {
	if len(b) < 124 {
		return ErrCertTooShort
	}

	// <cert-magic>
	if !bytes.Equal(b[:4], certMagic[:4]) {
		return ErrCertMagic
	}

	// <es-version>
	switch esVersion := binary.BigEndian.Uint16(b[4:6]); esVersion {
	case uint16(XSalsa20Poly1305):
		c.EsVersion = XSalsa20Poly1305
	case uint16(XChacha20Poly1305):
		c.EsVersion = XChacha20Poly1305
	default:
		return ErrEsVersion
	}

	// Ignore 6:8, <protocol-minor-version>
	// <signature>
	copy(c.Signature[:], b[8:72])
	// <resolver-pk>
	copy(c.ResolverPk[:], b[72:104])
	// <client-magic>
	copy(c.ClientMagic[:], b[104:112])
	// <serial>
	c.Serial = binary.BigEndian.Uint32(b[112:116])
	// <ts-start> <ts-end>
	c.NotBefore = binary.BigEndian.Uint32(b[116:120])
	c.NotAfter = binary.BigEndian.Uint32(b[120:124])

	// Deserialized with no issues.
	return nil
}

// VerifyDate checks if the certificate is valid at the current moment.
func (c *Cert) VerifyDate() bool {
	if c.NotBefore >= c.NotAfter {
		return false
	}
	now := uint32(time.Now().Unix())
	return now <= c.NotAfter && now >= c.NotBefore
}

// VerifySignature checks if the certificate is properly signed with the specified public key.
func (c *Cert) VerifySignature(publicKey ed25519.PublicKey) bool {
	signedData := make([]byte, 52)
	c.writeSigned(signedData)
	return ed25519.Verify(publicKey, signedData, c.Signature[:])
}

// Sign creates the certificate signature.
func (c *Cert) Sign(privateKey ed25519.PrivateKey) {
	signedData := make([]byte, 52)
	c.writeSigned(signedData)
	signature := ed25519.Sign(privateKey, signedData)
	copy(c.Signature[:64], signature[:64])
}

// String returns a string representation of the certificate.
func (c *Cert) String() string {
	return fmt.Sprintf("Certificate Serial=%d NotBefore=%s NotAfter=%s EsVersion=%s",
		c.Serial, time.Unix(int64(c.NotBefore), 0).String(),
		time.Unix(int64(c.NotAfter), 0).String(), c.EsVersion.String())
}

// writeSigned writes (<resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>)
func (c *Cert) writeSigned(dst []byte) {
	// <resolver-pk>
	copy(dst[:32], c.ResolverPk[:keySize])
	// <client-magic>
	copy(dst[32:40], c.ClientMagic[:clientMagicSize])
	// <serial>
	binary.BigEndian.PutUint32(dst[40:44], c.Serial)
	// <ts-start>
	binary.BigEndian.PutUint32(dst[44:48], c.NotBefore)
	// <ts-end>
	binary.BigEndian.PutUint32(dst[48:52], c.NotAfter)
}
