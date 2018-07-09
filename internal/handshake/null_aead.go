package handshake

import (
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// NewNullAEAD creates a new NullAEAD for IETF QUIC
func NewNullAEAD(
	connID protocol.ConnectionID,
	pers protocol.Perspective,
) (AEADWithPacketNumberCrypto, error) {
	aead, err := crypto.NewNullAEAD(connID, pers)
	if err != nil {
		return nil, err
	}
	return newAEADWithPacketNumberCrypto(aead), nil
}
