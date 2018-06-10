package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

var (
	errReceivedOmittedConnectionID = qerr.Error(qerr.InvalidPacketHeader, "receiving packets with omitted ConnectionID is not supported")
	errInvalidConnectionID         = qerr.Error(qerr.InvalidPacketHeader, "connection ID cannot be 0")
	errInvalidPacketNumberLen      = errors.New("invalid packet number length")
)

// writePublicHeader writes a Public Header.
func (h *Header) writePublicHeader(
	b *bytes.Buffer,
	pn protocol.PacketNumber,
	pnLen protocol.PacketNumberLen,
	pers protocol.Perspective,
) error {
	if h.VersionFlag && pers == protocol.PerspectiveServer {
		return errors.New("PublicHeader: Writing of Version Negotiation Packets not supported")
	}
	if h.ResetFlag {
		return errors.New("PublicHeader: Writing of Public Reset Packets not supported")
	}
	if !h.DestConnectionID.Equal(h.SrcConnectionID) {
		return fmt.Errorf("PublicHeader: SrcConnectionID must be equal to DestConnectionID")
	}
	if len(h.DestConnectionID) != 8 {
		return fmt.Errorf("PublicHeader: wrong length for Connection ID: %d (expected 8)", len(h.DestConnectionID))
	}

	publicFlagByte := uint8(0x00)
	if h.VersionFlag {
		publicFlagByte |= 0x01
	}
	if !h.OmitConnectionID {
		publicFlagByte |= 0x08
	}
	if len(h.DiversificationNonce) > 0 {
		if len(h.DiversificationNonce) != 32 {
			return errors.New("invalid diversification nonce length")
		}
		publicFlagByte |= 0x04
	}
	switch pnLen {
	case protocol.PacketNumberLen1:
		publicFlagByte |= 0x00
	case protocol.PacketNumberLen2:
		publicFlagByte |= 0x10
	case protocol.PacketNumberLen4:
		publicFlagByte |= 0x20
	default:
		return errInvalidPacketNumberLen
	}
	b.WriteByte(publicFlagByte)

	if !h.OmitConnectionID {
		b.Write(h.DestConnectionID)
	}
	if h.VersionFlag && pers == protocol.PerspectiveClient {
		utils.BigEndian.WriteUint32(b, uint32(h.Version))
	}
	if len(h.DiversificationNonce) > 0 {
		b.Write(h.DiversificationNonce)
	}

	switch pnLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(pn))
	case protocol.PacketNumberLen2:
		utils.BigEndian.WriteUint16(b, uint16(pn))
	case protocol.PacketNumberLen4:
		utils.BigEndian.WriteUint32(b, uint32(pn))
	}
	return nil
}

func readPublicHeaderPacketNumber(b *bytes.Reader, flagByte byte) (protocol.PacketNumber, protocol.PacketNumberLen, error) {
	var pnLen protocol.PacketNumberLen
	switch flagByte & 0x30 {
	case 0x00:
		pnLen = protocol.PacketNumberLen1
	case 0x10:
		pnLen = protocol.PacketNumberLen2
	case 0x20:
		pnLen = protocol.PacketNumberLen4
	default:
		return 0, 0, errInvalidPacketNumberLen
	}
	pn, err := utils.BigEndian.ReadUintN(b, uint8(pnLen))
	return protocol.PacketNumber(pn), pnLen, err
}

// parsePublicHeader parses a QUIC packet's Public Header.
// The packetSentBy is the perspective of the peer that sent this PublicHeader, i.e. if we're the server, packetSentBy should be PerspectiveClient.
func parsePublicHeader(b *bytes.Reader, packetSentBy protocol.Perspective) (*Header, error) {
	header := &Header{}

	// First byte
	publicFlagByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	header.ResetFlag = publicFlagByte&0x02 > 0
	header.VersionFlag = publicFlagByte&0x01 > 0

	// TODO: activate this check once Chrome sends the correct value
	// see https://github.com/lucas-clemente/quic-go/issues/232
	// if publicFlagByte&0x04 > 0 {
	// 	return nil, errors.New("diversification nonces should only be sent by servers")
	// }

	header.OmitConnectionID = publicFlagByte&0x08 == 0
	if header.OmitConnectionID && packetSentBy == protocol.PerspectiveClient {
		return nil, errReceivedOmittedConnectionID
	}

	// Connection ID
	if !header.OmitConnectionID {
		connID := make(protocol.ConnectionID, 8)
		if _, err := io.ReadFull(b, connID); err != nil {
			if err == io.ErrUnexpectedEOF {
				err = io.EOF
			}
			return nil, err
		}
		if connID[0] == 0 && connID[1] == 0 && connID[2] == 0 && connID[3] == 0 && connID[4] == 0 && connID[5] == 0 && connID[6] == 0 && connID[7] == 0 {
			return nil, errInvalidConnectionID
		}
		header.DestConnectionID = connID
		header.SrcConnectionID = connID
	}

	// Contrary to what the gQUIC wire spec says, the 0x4 bit only indicates the presence of the diversification nonce for packets sent by the server.
	// It doesn't have any meaning when sent by the client.
	if packetSentBy == protocol.PerspectiveServer && publicFlagByte&0x04 > 0 {
		if !header.VersionFlag && !header.ResetFlag {
			header.DiversificationNonce = make([]byte, 32)
			if _, err := io.ReadFull(b, header.DiversificationNonce); err != nil {
				return nil, err
			}
		}
	}

	// Version (optional)
	if !header.ResetFlag && header.VersionFlag {
		if packetSentBy == protocol.PerspectiveServer { // parse the version negotiation packet
			if b.Len() == 0 {
				return nil, qerr.Error(qerr.InvalidVersionNegotiationPacket, "empty version list")
			}
			if b.Len()%4 != 0 {
				return nil, qerr.InvalidVersionNegotiationPacket
			}
			header.IsVersionNegotiation = true
			header.SupportedVersions = make([]protocol.VersionNumber, 0)
			for {
				var versionTag uint32
				versionTag, err = utils.BigEndian.ReadUint32(b)
				if err != nil {
					break
				}
				v := protocol.VersionNumber(versionTag)
				header.SupportedVersions = append(header.SupportedVersions, v)
			}
			// a version negotiation packet doesn't have a packet number
			return header, nil
		}
		// packet was sent by the client. Read the version number
		var versionTag uint32
		versionTag, err = utils.BigEndian.ReadUint32(b)
		if err != nil {
			return nil, err
		}
		header.Version = protocol.VersionNumber(versionTag)
	}
	return header, nil
}

// getPublicHeaderLength gets the length of the publicHeader in bytes.
// It can only be called for regular packets.
func (h *Header) getPublicHeaderLength(pnLen protocol.PacketNumberLen, pers protocol.Perspective) protocol.ByteCount {
	length := protocol.ByteCount(1) // 1 byte for public flags
	if !h.OmitConnectionID {
		length += 8 // 8 bytes for the connection ID
	}
	// Version Number in packets sent by the client
	if h.VersionFlag {
		length += 4
	}
	length += protocol.ByteCount(len(h.DiversificationNonce))
	length += protocol.ByteCount(pnLen)
	return length
}

func (h *Header) logPublicHeader(logger utils.Logger) {
	ver := "(unset)"
	if h.Version != 0 {
		ver = h.Version.String()
	}
	logger.Debugf("\tPublic Header{ConnectionID: %s, Version: %s, DiversificationNonce: %#v}", h.DestConnectionID, ver, h.DiversificationNonce)
}
