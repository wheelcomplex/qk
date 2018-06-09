package wire

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header", func() {
	const (
		versionPublicHeader = protocol.Version39  // a QUIC version that uses the Public Header format
		versionIETFHeader   = protocol.VersionTLS // a QUIC version that uses the IETF Header format
	)

	Context("parsing", func() {
		It("parses an IETF draft Short Header, when the QUIC version supports TLS", func() {
			buf := &bytes.Buffer{}
			// use a Short Header, which isn't distinguishable from the gQUIC Public Header when looking at the type byte
			h := &Header{
				IsLongHeader:     false,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				KeyPhase:         1,
			}
			err := h.writeHeader(buf, 1, protocol.PacketNumberLen1)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeaderSentByClient(bytes.NewReader(buf.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.KeyPhase).To(BeEquivalentTo(1))
			Expect(hdr.IsPublicHeader).To(BeFalse())
		})

		It("parses an IETF draft header, when the version is not known, but it has Long Header format", func() {
			buf := &bytes.Buffer{}
			err := (&Header{
				IsLongHeader:     true,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				Type:             protocol.PacketType0RTT,
				Version:          0x1234,
			}).writeHeader(buf, 1, protocol.PacketNumberLen1)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(buf.Bytes())
			hdr, err := ParseHeaderSentByClient(r)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketType0RTT))
			Expect(hdr.IsPublicHeader).To(BeFalse())
			Expect(hdr.Version).To(Equal(protocol.VersionNumber(0x1234)))
		})

		It("reads the packet number for an IETF draft header", func() {
			buf := &bytes.Buffer{}
			hdr := &Header{
				IsLongHeader:     true,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				Type:             protocol.PacketType0RTT,
				Version:          0x1234,
			}
			err := hdr.writeHeader(buf, 0x1337, protocol.PacketNumberLen2)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(buf.Bytes())
			_, err = ParseHeaderSentByClient(r)
			Expect(err).ToNot(HaveOccurred())
			pn, pnLen, err := ReadPacketNumber(r, buf.Bytes()[0], versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(pn).To(Equal(protocol.PacketNumber(0x1337)))
			Expect(pnLen).To(Equal(protocol.PacketNumberLen2))
		})

		It("doesn't mistake packets with a Short Header for Version Negotiation Packets", func() {
			// make sure this packet could be mistaken for a Version Negotiation Packet, if we only look at the 0x1 bit
			buf := &bytes.Buffer{}
			err := (&Header{
				IsLongHeader:     false,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			}).writeHeader(buf, 1, protocol.PacketNumberLen1)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeaderSentByServer(bytes.NewReader(buf.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsPublicHeader).To(BeFalse())
		})

		It("parses a gQUIC Public Header, when the version is not known", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			buf := &bytes.Buffer{}
			err := (&Header{
				VersionFlag:      true,
				Version:          versionPublicHeader,
				DestConnectionID: connID,
				SrcConnectionID:  connID,
			}).writePublicHeader(buf, 1, protocol.PacketNumberLen1, protocol.PerspectiveClient)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeaderSentByClient(bytes.NewReader(buf.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.DestConnectionID).To(Equal(connID))
			Expect(hdr.SrcConnectionID).To(Equal(connID))
			Expect(hdr.Version).To(Equal(versionPublicHeader))
			Expect(hdr.IsPublicHeader).To(BeTrue())
		})

		It("parses a gQUIC Public Header", func() {
			connID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
			buf := &bytes.Buffer{}
			err := (&Header{
				DestConnectionID:     connID,
				SrcConnectionID:      connID,
				DiversificationNonce: bytes.Repeat([]byte{'f'}, 32),
			}).writePublicHeader(buf, 1, protocol.PacketNumberLen1, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeaderSentByServer(bytes.NewReader(buf.Bytes()))
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.DestConnectionID).To(Equal(connID))
			Expect(hdr.SrcConnectionID).To(Equal(connID))
			Expect(hdr.DiversificationNonce).To(HaveLen(32))
			Expect(hdr.IsPublicHeader).To(BeTrue())
		})

		It("reads the packet number for a gQUIC Public Header", func() {
			connID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
			buf := bytes.NewBuffer(make([]byte, 0, 100))
			hdr := &Header{
				DestConnectionID: connID,
				SrcConnectionID:  connID,
			}
			err := hdr.writePublicHeader(buf, 0x1337, protocol.PacketNumberLen2, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(buf.Bytes())
			_, err = ParseHeaderSentByServer(r)
			Expect(err).ToNot(HaveOccurred())
			pn, pnLen, err := ReadPacketNumber(r, buf.Bytes()[0], versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(pn).To(Equal(protocol.PacketNumber(0x1337)))
			Expect(pnLen).To(Equal(protocol.PacketNumberLen2))
		})

		It("errors when parsing the gQUIC header fails", func() {
			buf := &bytes.Buffer{}
			err := (&Header{
				VersionFlag:      true,
				Version:          versionPublicHeader,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			}).writePublicHeader(buf, 1, protocol.PacketNumberLen1, protocol.PerspectiveClient)
			Expect(err).ToNot(HaveOccurred())
			_, err = ParseHeaderSentByClient(bytes.NewReader(buf.Bytes()[0:12]))
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors when given no data", func() {
			_, err := ParseHeaderSentByServer(bytes.NewReader([]byte{}))
			Expect(err).To(MatchError(io.EOF))
			_, err = ParseHeaderSentByClient(bytes.NewReader([]byte{}))
			Expect(err).To(MatchError(io.EOF))
		})

		It("parses a gQUIC Version Negotiation Packet", func() {
			connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0xde, 0xca, 0xfb, 0xad}
			versions := []protocol.VersionNumber{0x13, 0x37}
			data := ComposeGQUICVersionNegotiation(connID, versions)
			hdr, err := ParseHeaderSentByServer(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsPublicHeader).To(BeTrue())
			Expect(hdr.DestConnectionID).To(Equal(connID))
			Expect(hdr.SrcConnectionID).To(Equal(connID))
			// in addition to the versions, the supported versions might contain a reserved version number
			for _, version := range versions {
				Expect(hdr.SupportedVersions).To(ContainElement(version))
			}
		})

		It("parses an IETF draft style Version Negotiation Packet", func() {
			destConnID := protocol.ConnectionID{1, 3, 3, 7, 1, 3, 3, 7}
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			versions := []protocol.VersionNumber{0x13, 0x37}
			data, err := ComposeVersionNegotiation(destConnID, srcConnID, versions)
			Expect(err).ToNot(HaveOccurred())
			hdr, err := ParseHeaderSentByServer(bytes.NewReader(data))
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsPublicHeader).To(BeFalse())
			Expect(hdr.IsVersionNegotiation).To(BeTrue())
			Expect(hdr.DestConnectionID).To(Equal(destConnID))
			Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
			Expect(hdr.Version).To(BeZero())
			// in addition to the versions, the supported versions might contain a reserved version number
			for _, version := range versions {
				Expect(hdr.SupportedVersions).To(ContainElement(version))
			}
		})
	})

	Context("writing", func() {
		It("writes a gQUIC Public Header", func() {
			buf := &bytes.Buffer{}
			hdr := &Header{
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			}
			err := hdr.Write(buf, 0x1337, protocol.PacketNumberLen2, protocol.PerspectiveServer, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(buf.Bytes())
			_, err = parsePublicHeader(r, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsPublicHeader).To(BeTrue())
			pn, pnLen, err := readPublicHeaderPacketNumber(r, buf.Bytes()[0])
			Expect(err).ToNot(HaveOccurred())
			Expect(pn).To(Equal(protocol.PacketNumber(0x1337)))
			Expect(pnLen).To(Equal(protocol.PacketNumberLen2))
		})

		It("writes a IETF draft header", func() {
			buf := &bytes.Buffer{}
			hdr := &Header{
				Type:             protocol.PacketTypeHandshake,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				KeyPhase:         1,
			}
			err := hdr.Write(buf, 0x1337, protocol.PacketNumberLen2, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			r := bytes.NewReader(buf.Bytes())
			_, err = ParseHeaderSentByServer(r)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsPublicHeader).To(BeFalse())
			pn, pnLen, err := readPacketNumber(r, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(pn).To(Equal(protocol.PacketNumber(0x1337)))
			Expect(pnLen).To(Equal(protocol.PacketNumberLen2))
		})
	})

	Context("getting the length", func() {
		It("get the length of a gQUIC Public Header", func() {
			buf := &bytes.Buffer{}
			hdr := &Header{
				DestConnectionID:     protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:      protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				DiversificationNonce: bytes.Repeat([]byte{'f'}, 32),
			}
			pnLen := protocol.PacketNumberLen4
			err := hdr.Write(buf, 1, pnLen, protocol.PerspectiveServer, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			publicHeaderLen, err := hdr.getPublicHeaderLength(pnLen, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			ietfHeaderLen := hdr.getHeaderLength(pnLen)
			Expect(publicHeaderLen).ToNot(Equal(ietfHeaderLen)) // make sure we can distinguish between the two header types
			len, err := hdr.GetLength(pnLen, protocol.PerspectiveServer, versionPublicHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(publicHeaderLen))
		})

		It("get the length of a a IETF draft header", func() {
			buf := &bytes.Buffer{}
			hdr := &Header{
				IsLongHeader:     true,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				KeyPhase:         1,
			}
			pnLen := protocol.PacketNumberLen4
			err := hdr.Write(buf, 1, pnLen, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			publicHeaderLen, err := hdr.getPublicHeaderLength(pnLen, protocol.PerspectiveServer)
			Expect(err).ToNot(HaveOccurred())
			ietfHeaderLen := hdr.getHeaderLength(pnLen)
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeaderLen).ToNot(Equal(ietfHeaderLen)) // make sure we can distinguish between the two header types
			len, err := hdr.GetLength(pnLen, protocol.PerspectiveServer, versionIETFHeader)
			Expect(err).ToNot(HaveOccurred())
			Expect(len).To(Equal(ietfHeaderLen))
		})
	})

	Context("logging", func() {
		var (
			buf    *bytes.Buffer
			logger utils.Logger
		)

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			logger = utils.DefaultLogger
			logger.SetLogLevel(utils.LogLevelDebug)
			log.SetOutput(buf)
		})

		AfterEach(func() {
			log.SetOutput(os.Stdout)
		})

		It("logs an IETF draft header", func() {
			(&Header{
				IsLongHeader:     true,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				Version:          0x1337,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header"))
		})

		It("logs a Public Header", func() {
			(&Header{
				IsPublicHeader:   true,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Public Header"))
		})
	})
})
