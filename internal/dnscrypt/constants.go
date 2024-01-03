package dnscrypt

// Error represents a DNSCrypt error.
type Error string

func (e Error) Error() string { return "dnscrypt: " + string(e) }

const (
	// ErrQueryTooLarge indicates that the DNS query is larger than the maximum allowed size.
	ErrQueryTooLarge = Error("DNSCrypt query is too large")

	// ErrEsVersion indicates that the certificate contains an unsupported es-version.
	ErrEsVersion = Error("unsupported es-version")

	// ErrInvalidDate indicates that the certificate is not valid for the current time.
	ErrInvalidDate = Error("certificate has invalid ts-start or ts-end")

	// ErrInvalidCertSignature indicates that the certificate has an invalid signature.
	ErrInvalidCertSignature = Error("certificate has invalid signature")

	// ErrInvalidQuery indicates that it failed to decrypt a DNSCrypt query.
	ErrInvalidQuery = Error("DNSCrypt query is invalid and cannot be decrypted")

	// ErrInvalidClientMagic indicates that client-magic does not match.
	ErrInvalidClientMagic = Error("DNSCrypt query contains invalid client magic")

	// ErrInvalidResolverMagic indicates that server-magic does not match.
	ErrInvalidResolverMagic = Error("DNSCrypt response contains invalid resolver magic")

	// ErrInvalidResponse indicates that it failed to decrypt a DNSCrypt response.
	ErrInvalidResponse = Error("DNSCrypt response is invalid and cannot be decrypted")

	// ErrInvalidPadding indicates that it failed to unpad a query.
	ErrInvalidPadding = Error("invalid padding")

	// ErrInvalidDNSStamp represents an invalid DNS stamp.
	ErrInvalidDNSStamp = Error("invalid DNS stamp")

	// ErrFailedToFetchCert indicates that it failed to fetch DNSCrypt certificate.
	ErrFailedToFetchCert = Error("failed to fetch DNSCrypt certificate")

	// ErrCertTooShort indicates that it failed to deserialize a certificate due to its length.
	ErrCertTooShort = Error("certificate is too short")

	// ErrCertMagic represents an invalid certificate magic.
	ErrCertMagic = Error("invalid certificate magic")
)

const (
	// minUDPQuestionSize is a variable length, initially set to 256 bytes, and
	// must be a multiple of 64 bytes. (see https://dnscrypt.info/protocol)
	minUDPQuestionSize = 256

	// minDNSPacketSize is the minimum possible DNS packet size.
	minDNSPacketSize = 12 + 5

	// keySize represents the size of the public and secret keys, which are 32 bytes long in storage.
	keySize = 32

	// sharedKeySize is the size of the shared key used to encrypt/decrypt messages.
	sharedKeySize = 32

	// clientMagicSize is the size of the client magic, which is the first 8 bytes of a client query.
	clientMagicSize = 8

	// nonceSize is the size of the nonce when using X25519-XSalsa20Poly1305.
	nonceSize = 24

	// resolverMagicSize is the size of the first 8 bytes of every DNSCrypt response, which must match resolverMagic.
	resolverMagicSize = 8
)

var (
	// certMagic is a byte sequence that must be in the beginning of the serialized certificate.
	certMagic = [4]byte{0x44, 0x4e, 0x53, 0x43}

	// resolverMagic is a byte sequence that must be in the beginning of every response.
	resolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
)

// CryptoConstruction represents the encryption algorithm (either XSalsa20Poly1305 or XChacha20Poly1305).
type CryptoConstruction uint16

const (
	// UndefinedConstruction is the default value for an empty CertInfo.
	UndefinedConstruction CryptoConstruction = iota
	// XSalsa20Poly1305 encryption.
	XSalsa20Poly1305 CryptoConstruction = 0x0001
	// XChacha20Poly1305 encryption.
	XChacha20Poly1305 CryptoConstruction = 0x0002
)

func (c CryptoConstruction) String() string {
	switch c {
	case XChacha20Poly1305:
		return "XChacha20Poly1305"
	case XSalsa20Poly1305:
		return "XSalsa20Poly1305"
	default:
		return "Unknown"
	}
}
