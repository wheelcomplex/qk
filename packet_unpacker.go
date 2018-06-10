package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpackedPacket struct {
	packetNumber    protocol.PacketNumber
	encryptionLevel protocol.EncryptionLevel
	frames          []wire.Frame
}

type gQUICAEAD interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
}

type quicAEAD interface {
	OpenHandshake(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
	Open1RTT(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
}

type packetUnpackerBase struct {
	largestRcvdPacketNumber protocol.PacketNumber

	version protocol.VersionNumber
}

func (u *packetUnpackerBase) parseFrames(decrypted []byte, pn protocol.PacketNumber, pnLen protocol.PacketNumberLen) ([]wire.Frame, error) {
	r := bytes.NewReader(decrypted)
	if r.Len() == 0 {
		return nil, qerr.MissingPayload
	}

	fs := make([]wire.Frame, 0, 2)
	// Read all frames in the packet
	for {
		frame, err := wire.ParseNextFrame(r, pn, pnLen, u.version)
		if err != nil {
			return nil, err
		}
		if frame == nil {
			break
		}
		fs = append(fs, frame)
	}
	return fs, nil
}

func (u *packetUnpackerBase) inferPacketNumber(pnLen protocol.PacketNumberLen, wirePN protocol.PacketNumber) protocol.PacketNumber {
	return protocol.InferPacketNumber(pnLen, u.largestRcvdPacketNumber, wirePN, u.version)
}

// The packetUnpackerGQUIC unpacks gQUIC packets.
type packetUnpackerGQUIC struct {
	packetUnpackerBase
	aead gQUICAEAD
}

var _ unpacker = &packetUnpackerGQUIC{}

func newPacketUnpackerGQUIC(aead gQUICAEAD, version protocol.VersionNumber) unpacker {
	return &packetUnpackerGQUIC{
		packetUnpackerBase: packetUnpackerBase{version: version},
		aead:               aead,
	}
}

func (u *packetUnpackerGQUIC) Unpack(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	pn, pnLen, err := wire.ReadPacketNumber(bytes.NewReader(data[hdr.ParsedLen:]), data[0], u.version)
	if err != nil {
		return nil, err
	}
	pn = u.inferPacketNumber(pnLen, pn)
	payloadOffset := hdr.ParsedLen + int(pnLen)
	decrypted, encLevel, err := u.aead.Open(data[payloadOffset:payloadOffset], data[payloadOffset:], pn, data[:payloadOffset])
	if err != nil {
		// Wrap err in quicError so that public reset is sent by session
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}

	u.largestRcvdPacketNumber = utils.MaxPacketNumber(u.largestRcvdPacketNumber, pn)
	fs, err := u.parseFrames(decrypted, pn, pnLen)
	if err != nil {
		return nil, err
	}

	return &unpackedPacket{
		packetNumber:    pn,
		encryptionLevel: encLevel,
		frames:          fs,
	}, nil
}

// The packetUnpacker unpacks IETF QUIC packets.
type packetUnpacker struct {
	packetUnpackerBase
	aead quicAEAD
}

var _ unpacker = &packetUnpacker{}

func newPacketUnpacker(aead quicAEAD, version protocol.VersionNumber) unpacker {
	return &packetUnpacker{
		packetUnpackerBase: packetUnpackerBase{version: version},
		aead:               aead,
	}
}

func (u *packetUnpacker) Unpack(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	pn, pnLen, err := wire.ReadPacketNumber(bytes.NewReader(data[hdr.ParsedLen:]), data[0], u.version)
	if err != nil {
		return nil, err
	}
	pn = u.inferPacketNumber(pnLen, pn)
	payloadOffset := hdr.ParsedLen + int(pnLen)

	buf := *getPacketBuffer()
	buf = buf[:0]
	defer putPacketBuffer(&buf)

	var decrypted []byte
	var encryptionLevel protocol.EncryptionLevel
	if hdr.IsLongHeader {
		decrypted, err = u.aead.OpenHandshake(buf, data[payloadOffset:], pn, data[:payloadOffset])
		encryptionLevel = protocol.EncryptionUnencrypted
	} else {
		decrypted, err = u.aead.Open1RTT(buf, data[payloadOffset:], pn, data[:payloadOffset])
		encryptionLevel = protocol.EncryptionForwardSecure
	}
	if err != nil {
		// Wrap err in quicError so that public reset is sent by session
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}

	u.largestRcvdPacketNumber = utils.MaxPacketNumber(u.largestRcvdPacketNumber, pn)
	fs, err := u.parseFrames(decrypted, pn, pnLen)
	if err != nil {
		return nil, err
	}

	return &unpackedPacket{
		packetNumber:    pn,
		encryptionLevel: encryptionLevel,
		frames:          fs,
	}, nil
}
