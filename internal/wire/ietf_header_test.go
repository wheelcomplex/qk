package wire

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("IETF QUIC Header", func() {
	srcConnID := protocol.ConnectionID(bytes.Repeat([]byte{'f'}, protocol.ConnectionIDLen))

	appendPacketNumber := func(data []byte, pn protocol.PacketNumber, pnLen protocol.PacketNumberLen) []byte {
		buf := &bytes.Buffer{}
		utils.WriteVarIntPacketNumber(buf, pn, pnLen)
		return append(data, buf.Bytes()...)
	}

	Context("parsing", func() {
		Context("Version Negotiation Packets", func() {
			It("parses", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				versions := []protocol.VersionNumber{0x22334455, 0x33445566}
				data, err := ComposeVersionNegotiation(connID, connID, versions)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data)
				h, err := parseHeader(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsVersionNegotiation).To(BeTrue())
				Expect(h.Version).To(BeZero())
				Expect(h.DestConnectionID).To(Equal(connID))
				Expect(h.SrcConnectionID).To(Equal(connID))
				for _, v := range versions {
					Expect(h.SupportedVersions).To(ContainElement(v))
				}
			})

			It("errors if it contains versions of the wrong length", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				versions := []protocol.VersionNumber{0x22334455, 0x33445566}
				data, err := ComposeVersionNegotiation(connID, connID, versions)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data[:len(data)-2])
				_, err = parseHeader(b)
				Expect(err).To(MatchError(qerr.InvalidVersionNegotiationPacket))
			})

			It("errors if the version list is empty", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				versions := []protocol.VersionNumber{0x22334455}
				data, err := ComposeVersionNegotiation(connID, connID, versions)
				Expect(err).ToNot(HaveOccurred())
				// remove 8 bytes (two versions), since ComposeVersionNegotiation also added a reserved version number
				_, err = parseHeader(bytes.NewReader(data[:len(data)-8]))
				Expect(err).To(MatchError("InvalidVersionNegotiationPacket: empty version list"))
			})
		})

		Context("long headers", func() {
			It("parses a long header", func() {
				data := []byte{
					0x80 ^ uint8(protocol.PacketTypeInitial),
					0x1, 0x2, 0x3, 0x4, // version number
					0x55,                                           // connection ID lengths
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // destination connection ID
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // source connection ID
				}
				data = append(data, encodeVarInt(0x1337)...) // length
				b := bytes.NewReader(data)
				h, err := parseHeader(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.Type).To(Equal(protocol.PacketTypeInitial))
				Expect(h.IsLongHeader).To(BeTrue())
				Expect(h.OmitConnectionID).To(BeFalse())
				Expect(h.DestConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}))
				Expect(h.SrcConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}))
				Expect(h.Length).To(Equal(protocol.ByteCount(0x1337)))
				Expect(h.Version).To(Equal(protocol.VersionNumber(0x1020304)))
				Expect(h.IsVersionNegotiation).To(BeFalse())
				// pn, pnLen, err := readPacketNumber(b, 0)
				// Expect(err).ToNot(HaveOccurred())
				// Expect(pn).To(Equal(protocol.PacketNumber(0x1337)))
				// Expect(pnLen).To(Equal(protocol.PacketNumberLen4))
				Expect(b.Len()).To(BeZero())
			})

			It("parses a long header without a destination connection ID", func() {
				data := []byte{
					0x80 ^ uint8(protocol.PacketTypeInitial),
					0x1, 0x2, 0x3, 0x4, // version number
					0x01,                   // connection ID lengths
					0xde, 0xad, 0xbe, 0xef, // source connection ID
				}
				data = append(data, encodeVarInt(0x42)...) // length
				data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
				b := bytes.NewReader(data)
				h, err := parseHeader(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.SrcConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}))
				Expect(h.DestConnectionID).To(BeEmpty())
			})

			It("parses a long header with no connection IDs", func() {
				data := []byte{
					0x80 ^ uint8(protocol.PacketTypeInitial),
					0x1, 0x2, 0x3, 0x4, // version number
					0x0, // connection ID lengths
				}
				data = append(data, encodeVarInt(0x42)...) // length
				b := bytes.NewReader(data)
				h, err := parseHeader(b)
				Expect(h.SrcConnectionID).To(BeEmpty())
				Expect(h.DestConnectionID).To(BeEmpty())
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Len()).To(BeZero())
			})

			It("parses a long header without a source connection ID", func() {
				data := []byte{
					0x80 ^ uint8(protocol.PacketTypeInitial),
					0x1, 0x2, 0x3, 0x4, // version number
					0x70,                          // connection ID lengths
					1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // source connection ID
				}
				data = append(data, encodeVarInt(0x42)...) // length
				b := bytes.NewReader(data)
				h, err := parseHeader(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.SrcConnectionID).To(BeEmpty())
				Expect(h.DestConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects packets sent with an unknown packet type", func() {
				buf := &bytes.Buffer{}
				err := (&Header{
					IsLongHeader:    true,
					Type:            42,
					SrcConnectionID: srcConnID,
					Version:         versionIETFFrames,
				}).Write(buf, 1, protocol.PacketNumberLen1, protocol.PerspectiveClient)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(buf.Bytes())
				_, err = parseHeader(b)
				Expect(err).To(MatchError("InvalidPacketHeader: Received packet with invalid packet type: 42"))
			})

			It("errors on EOF", func() {
				data := []byte{
					0x80 ^ uint8(protocol.PacketTypeInitial),
					0x1, 0x2, 0x3, 0x4, // version number
					0x55,                                           // connection ID lengths
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // destination connection ID
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // source connection ID
				}
				data = appendPacketNumber(data, 0x1337, protocol.PacketNumberLen4)
				for i := 0; i < len(data); i++ {
					_, err := parseHeader(bytes.NewReader(data[:i]))
					Expect(err).To(Equal(io.EOF))
				}
			})
		})

		Context("short headers", func() {
			It("reads a short header with a connection ID", func() {
				data := []byte{
					0x30,                                           // 1 byte packet number
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
				}
				b := bytes.NewReader(data)
				h, err := parseHeader(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.KeyPhase).To(Equal(0))
				Expect(h.OmitConnectionID).To(BeFalse())
				Expect(h.DestConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}))
				Expect(h.SrcConnectionID).To(BeEmpty())
				Expect(h.IsVersionNegotiation).To(BeFalse())
				Expect(b.Len()).To(BeZero())
			})

			It("reads the Key Phase Bit", func() {
				data := []byte{
					0x30 ^ 0x40,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
				}
				b := bytes.NewReader(data)
				h, err := parseHeader(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				Expect(h.KeyPhase).To(Equal(1))
				Expect(b.Len()).To(BeZero())
			})

			It("reads the packet number", func() {
				data := []byte{
					0x30 ^ 0x1,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
				}
				data = appendPacketNumber(data, 0x1337, protocol.PacketNumberLen2)
				b := bytes.NewReader(data)
				h, err := parseHeader(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(h.IsLongHeader).To(BeFalse())
				pn, pnLen, err := readPacketNumber(b, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(pn).To(Equal(protocol.PacketNumber(0x1337)))
				Expect(pnLen).To(Equal(protocol.PacketNumberLen2))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects headers that have bit 3,4 and 5 set incorrectly", func() {
				data := []byte{
					0x38,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
				}
				data = appendPacketNumber(data, 1234, protocol.PacketNumberLen2)
				b := bytes.NewReader(data)
				_, err := parseHeader(b)
				Expect(err).To(MatchError("invalid bits 3, 4 and 5"))
			})

			It("errors on EOF", func() {
				data := []byte{
					0x30,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
				}
				for i := 0; i < len(data); i++ {
					_, err := parseHeader(bytes.NewReader(data[:i]))
					Expect(err).To(Equal(io.EOF))
				}
			})
		})
	})

	Context("writing", func() {
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
		})

		Context("long header", func() {
			It("writes", func() {
				err := (&Header{
					IsLongHeader:     true,
					Type:             0x5,
					DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x0, 0x0, 0x13, 0x37},
					Length:           0xcafe,
					Version:          0x1020304,
				}).writeHeader(buf, 0xdecaf, protocol.PacketNumberLen4)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{
					0x80 ^ 0x5,
					0x1, 0x2, 0x3, 0x4, // version number
					0x35,                               // connection ID lengths
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // dest connection ID
					0xde, 0xca, 0xfb, 0xad, 0x0, 0x0, 0x13, 0x37, // source connection ID
				}
				expected = append(expected, encodeVarInt(0xcafe)...) // length
				expected = appendPacketNumber(expected, 0xdecaf, protocol.PacketNumberLen4)
				Expect(buf.Bytes()).To(Equal(expected))
			})

			It("refuses to write a header with a too short connection ID", func() {
				err := (&Header{
					IsLongHeader:     true,
					Type:             0x5,
					SrcConnectionID:  srcConnID,
					DestConnectionID: protocol.ConnectionID{1, 2, 3}, // connection IDs must be at least 4 bytes long
					Version:          0x1020304,
				}).writeHeader(buf, 1, protocol.PacketNumberLen1)
				Expect(err).To(MatchError("invalid connection ID length: 3 bytes"))
			})

			It("refuses to write a header with a too long connection ID", func() {
				err := (&Header{
					IsLongHeader:     true,
					Type:             0x5,
					SrcConnectionID:  srcConnID,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}, // connection IDs must be at most 18 bytes long
					Version:          0x1020304,
				}).writeHeader(buf, 1, protocol.PacketNumberLen1)
				Expect(err).To(MatchError("invalid connection ID length: 19 bytes"))
			})

			It("writes a header with an 18 byte connection ID", func() {
				err := (&Header{
					IsLongHeader:     true,
					Type:             0x5,
					SrcConnectionID:  srcConnID,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}, // connection IDs must be at most 18 bytes long
					Version:          0x1020304,
				}).writeHeader(buf, 1, protocol.PacketNumberLen1)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(ContainSubstring(string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18})))
			})
		})

		Context("short header", func() {
			It("writes a header with connection ID", func() {
				err := (&Header{
					DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
				}).writeHeader(buf, 0x42, protocol.PacketNumberLen1)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{
					0x30,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
				}
				expected = appendPacketNumber(expected, 0x42, protocol.PacketNumberLen1)
				Expect(buf.Bytes()).To(Equal(expected))
			})

			It("writes a header without connection ID", func() {
				err := (&Header{}).writeHeader(buf, 0x42, protocol.PacketNumberLen1)
				Expect(err).ToNot(HaveOccurred())
				expected := []byte{0x30}
				expected = appendPacketNumber(expected, 0x42, protocol.PacketNumberLen1)
				Expect(buf.Bytes()).To(Equal(expected))
			})

			It("errors when given an invalid packet number length", func() {
				err := (&Header{
					OmitConnectionID: true,
				}).writeHeader(buf, 0xdecafbad, protocol.PacketNumberLen(3))
				Expect(err).To(MatchError("invalid packet number length: 3"))
			})

			It("writes the Key Phase Bit", func() {
				err := (&Header{
					KeyPhase:         1,
					OmitConnectionID: true,
				}).writeHeader(buf, 1, protocol.PacketNumberLen1)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()[0]).To(Equal(byte(0x30 | 0x40)))
			})
		})
	})

	Context("length", func() {
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
		})

		It("has the right length for the long header, for a short Length field", func() {
			h := &Header{
				IsLongHeader:     true,
				Length:           1,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* conn ID len */ + 8 /* dest conn id */ + 8 /* src conn id */ + 1 /* length */
			Expect(h.getHeaderLength()).To(BeEquivalentTo(expectedLen))
			err := h.writeHeader(buf, 1, protocol.PacketNumberLen2)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(expectedLen + 2))
		})

		It("has the right length for the long header, for a long Length field", func() {
			h := &Header{
				IsLongHeader:     true,
				Length:           1500,
				DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* conn ID len */ + 8 /* dest conn id */ + 8 /* src conn id */ + 2 /* length */
			Expect(h.getHeaderLength()).To(BeEquivalentTo(expectedLen))
			err := h.writeHeader(buf, 1, protocol.PacketNumberLen4)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(expectedLen + 4))
		})

		It("has the right length for a short header containing a connection ID", func() {
			h := &Header{DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}}
			expectedLen := 1 + 8
			Expect(h.getHeaderLength()).To(BeEquivalentTo(expectedLen))
			err := h.writeHeader(buf, 1, protocol.PacketNumberLen4)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(expectedLen + 4))
		})

		It("has the right length for a short header without a connection ID", func() {
			h := &Header{OmitConnectionID: true}
			expectedLen := 1
			Expect(h.getHeaderLength()).To(BeEquivalentTo(expectedLen))
			err := h.writeHeader(buf, 42, protocol.PacketNumberLen2)
			Expect(err).ToNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(expectedLen + 2))
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

		It("logs version negotiation packets", func() {
			destConnID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
			srcConnID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x013, 0x37, 0x13, 0x37}
			data, err := ComposeVersionNegotiation(destConnID, srcConnID, []protocol.VersionNumber{0x12345678, 0x87654321})
			Expect(err).ToNot(HaveOccurred())
			hdr, err := parseLongHeader(bytes.NewReader(data[1:]), data[0])
			Expect(err).ToNot(HaveOccurred())
			hdr.logHeader(logger)
			Expect(buf.String()).To(ContainSubstring("VersionNegotiationPacket{DestConnectionID: 0xdeadbeefcafe1337, SrcConnectionID: 0xdecafbad13371337"))
			Expect(buf.String()).To(ContainSubstring("0x12345678"))
			Expect(buf.String()).To(ContainSubstring("0x87654321"))
		})

		It("logs Long Headers", func() {
			(&Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				Length:           54321,
				DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
				SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x013, 0x37, 0x13, 0x37},
				Version:          0xfeed,
			}).logHeader(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Handshake, DestConnectionID: 0xdeadbeefcafe1337, SrcConnectionID: 0xdecafbad13371337, Length: 54321, Version: 0xfeed}"))
		})

		It("logs Short Headers containing a connection ID", func() {
			(&Header{
				KeyPhase:         1,
				DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
			}).logHeader(logger)
			Expect(buf.String()).To(ContainSubstring("Short Header{DestConnectionID: 0xdeadbeefcafe1337, KeyPhase: 1}"))
		})
	})
})
