package crypto

import "github.com/lucas-clemente/quic-go/internal/protocol"

// An AEAD implements QUIC's authenticated encryption and associated data
type AEAD interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	Overhead() int
}

// A CTR implements the CTR mode needed QUIC's packet number encryption.
// Encryption and decryption is done in-place.
type ctr interface {
	Encrypt(plain, iv []byte) error
	Decrypt(ciphertext, iv []byte) error
	CTRIVSize() int
}

// AEADCTR is an AEAD that also implements the CTR for QUIC's packet number encryption.
type AEADCTR interface {
	AEAD
	ctr
}
