package handshake

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type aead struct {
	aeadctr crypto.AEADCTR
}

var _ AEADWithPacketNumberCrypto = &aead{}

func newAEADWithPacketNumberCrypto(aeadctr crypto.AEADCTR) AEADWithPacketNumberCrypto {
	return &aead{aeadctr: aeadctr}
}

func (a *aead) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	return a.aeadctr.Open(dst, src, packetNumber, associatedData)
}

func (a *aead) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	return a.aeadctr.Seal(dst, src, packetNumber, associatedData)
}

func (a *aead) Overhead() int {
	return a.aeadctr.Overhead()
}

func (a *aead) DecryptPacketNumber(data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, error) {
	var b [4]byte
	sample, err := a.getSample(data)
	if err != nil {
		return 0, 0, err
	}
	copy(b[:], data[:4])
	a.aeadctr.Decrypt(b[:], sample)
	return utils.ReadVarIntPacketNumber(bytes.NewReader(b[:]))
}

func (a *aead) EncryptPacketNumber(data []byte, pnLen protocol.PacketNumberLen) error {
	sample, err := a.getSample(data)
	if err != nil {
		return err
	}
	return a.aeadctr.Encrypt(data[:int(pnLen)], sample)
}

func (a *aead) getSample(data []byte) ([]byte, error) {
	sampleLength := a.aeadctr.CTRIVSize()
	offset := 4
	if offset+sampleLength > len(data) {
		offset = len(data) - sampleLength
	}
	if offset < 0 {
		return nil, fmt.Errorf("calculated too small packet number encryption sampling offset: %d", offset)
	}
	return data[offset : offset+sampleLength], nil
}
