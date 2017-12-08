package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NEW_CONNECTION_ID frame", func() {
	token := [16]byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}

	Context("when parsing", func() {
		It("accepts sample frame", func() {
			data := []byte{0x0b}
			data = append(data, encodeVarInt(0x12345678)...)                               // sequence
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // connection ID
			data = append(data, token[:]...)                                               // stateless reset token
			b := bytes.NewReader(data)
			frame, err := ParseNewConnectionIDFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Sequence).To(BeEquivalentTo(0x12345678))
			Expect(frame.ConnectionID).To(Equal(protocol.ConnectionID(0xdeadbeefcafe1337)))
			Expect(frame.StatelessResetToken).To(Equal(token))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x0b}
			data = append(data, encodeVarInt(0x1234)...)                                   // sequence
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // connection ID
			data = append(data, bytes.Repeat([]byte{0}, 16)...)                            // stateless reset token
			_, err := ParseNewConnectionIDFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			for i := range data {
				_, err := ParseNewConnectionIDFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := NewConnectionIDFrame{
				Sequence:            0x87654321,
				ConnectionID:        0xdecafbad,
				StatelessResetToken: token,
			}
			frame.Write(b, versionIETFFrames)
			expected := []byte{0x0b}
			expected = append(expected, encodeVarInt(0x87654321)...)
			expected = append(expected, []byte{0x0, 0x0, 0x0, 0x0, 0xde, 0xca, 0xfb, 0xad}...)
			expected = append(expected, token[:]...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := NewConnectionIDFrame{
				Sequence:            10,
				ConnectionID:        0xdecafbad,
				StatelessResetToken: token,
			}
			Expect(frame.MinLength(versionIETFFrames)).To(Equal(1 + 8 + 16 + utils.VarIntLen(10)))
		})
	})
})
