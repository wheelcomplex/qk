package quic

import (
	"bytes"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Unpacker (for gQUIC)", func() {
	var (
		unpacker *packetUnpackerGQUIC
		aead     *MockGQUICAEAD
	)

	getHeader := func(pn protocol.PacketNumber) (*wire.Header, []byte) {
		buf := &bytes.Buffer{}
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		hdr := &wire.Header{
			SrcConnectionID:  connID,
			DestConnectionID: connID,
			Version:          versionGQUICFrames,
		}
		err := hdr.Write(buf, pn, protocol.PacketNumberLen4, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())
		hdr.Raw = buf.Bytes()[:buf.Len()-4]
		return hdr, buf.Bytes()
	}

	BeforeEach(func() {
		aead = NewMockGQUICAEAD(mockCtrl)
		unpacker = newPacketUnpackerGQUIC(aead, versionGQUICFrames).(*packetUnpackerGQUIC)
	})

	It("errors if the packet doesn't contain any payload", func() {
		payload := []byte("foobar")
		hdr, raw := getHeader(10)
		data := append(raw, payload...)
		aead.EXPECT().Open(gomock.Any(), payload, protocol.PacketNumber(10), raw).Return([]byte{}, protocol.EncryptionForwardSecure, nil)
		_, err := unpacker.Unpack(hdr, data)
		Expect(err).To(MatchError(qerr.MissingPayload))
	})

	It("saves the encryption level", func() {
		payload := []byte("foobar")
		hdr, raw := getHeader(1337)
		data := append(raw, payload...)
		aead.EXPECT().Open(gomock.Any(), payload, protocol.PacketNumber(1337), raw).Return([]byte{0}, protocol.EncryptionSecure, nil)
		packet, err := unpacker.Unpack(hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionSecure))
	})

	It("unpacks the frames", func() {
		payload := []byte("foobar")
		buf := &bytes.Buffer{}
		(&wire.PingFrame{}).Write(buf, versionGQUICFrames)
		(&wire.BlockedFrame{}).Write(buf, versionGQUICFrames)
		hdr, raw := getHeader(1337)
		data := append(raw, payload...)
		aead.EXPECT().Open(gomock.Any(), payload, protocol.PacketNumber(1337), raw).Return(buf.Bytes(), protocol.EncryptionForwardSecure, nil)
		packet, err := unpacker.Unpack(hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{&wire.PingFrame{}, &wire.BlockedFrame{}}))
	})
})

var _ = Describe("Packet Unpacker (for IETF QUIC)", func() {
	var (
		unpacker *packetUnpacker
		aead     *MockQuicAEAD
	)

	getHeader := func(pn protocol.PacketNumber) (*wire.Header, []byte) {
		buf := &bytes.Buffer{}
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		hdr := &wire.Header{
			SrcConnectionID:  connID,
			DestConnectionID: connID,
			Version:          versionIETFFrames,
		}
		err := hdr.Write(buf, pn, protocol.PacketNumberLen4, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())
		hdr.Raw = buf.Bytes()[:buf.Len()-4]
		return hdr, buf.Bytes()
	}

	BeforeEach(func() {
		aead = NewMockQuicAEAD(mockCtrl)
		unpacker = newPacketUnpacker(aead, versionIETFFrames).(*packetUnpacker)
	})

	It("errors if the packet doesn't contain any payload", func() {
		payload := []byte("foobar")
		hdr, raw := getHeader(10)
		data := append(raw, payload...)
		aead.EXPECT().Open1RTT(gomock.Any(), payload, protocol.PacketNumber(10), raw).Return([]byte{}, nil)
		_, err := unpacker.Unpack(hdr, data)
		Expect(err).To(MatchError(qerr.MissingPayload))
	})

	It("opens handshake packets", func() {
		payload := []byte("foobar")
		hdr, raw := getHeader(10)
		data := append(raw, payload...)
		hdr.IsLongHeader = true
		aead.EXPECT().OpenHandshake(gomock.Any(), payload, protocol.PacketNumber(10), raw).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionUnencrypted))
	})

	It("unpacks the frames", func() {
		payload := []byte("foobar")
		hdr, raw := getHeader(1337)
		data := append(raw, payload...)
		buf := &bytes.Buffer{}
		(&wire.PingFrame{}).Write(buf, versionIETFFrames)
		(&wire.BlockedFrame{}).Write(buf, versionIETFFrames)
		aead.EXPECT().Open1RTT(gomock.Any(), payload, protocol.PacketNumber(1337), raw).Return(buf.Bytes(), nil)
		packet, err := unpacker.Unpack(hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{&wire.PingFrame{}, &wire.BlockedFrame{}}))
	})
})
