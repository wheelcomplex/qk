package handshake

import (
	"bytes"
	"crypto/rand"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cookie Generator", func() {
	var alice, bob AEADWithPacketNumberCrypto

	BeforeEach(func() {
		connID := protocol.ConnectionID{1, 2, 3, 4}
		aliceAEAD, err := crypto.NewNullAEAD(connID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		alice = newAEADWithPacketNumberCrypto(aliceAEAD)
		bobAEAD, err := crypto.NewNullAEAD(connID, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())
		bob = newAEADWithPacketNumberCrypto(bobAEAD)
	})

	It("encrypts and decrypts", func() {
		pn := protocol.PacketNumber(0x1337)
		plain := []byte("foobar")
		ciphertext := make([]byte, 0, 100)
		alice.Seal(ciphertext, plain, pn, []byte("aad"))
	})

	It("encrypts and decrypts a packet number", func() {
		pn := protocol.PacketNumber(0xbeef42)
		b := &bytes.Buffer{}
		Expect(utils.WriteVarIntPacketNumber(b, pn, protocol.PacketNumberLen4)).To(Succeed())
		packet := make([]byte, 100)
		rand.Read(packet)
		copy(packet[0:4], b.Bytes())
		err := alice.EncryptPacketNumber(packet, protocol.PacketNumberLen4)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet[0:4]).ToNot(Equal(b.Bytes())) // make sure the ciphertext is different from the cleartext
		pnDecrypted, pnLen, err := bob.DecryptPacketNumber(packet)
		Expect(err).ToNot(HaveOccurred())
		Expect(pnLen).To(Equal(protocol.PacketNumberLen4))
		Expect(pnDecrypted).To(Equal(pn))
	})

	It("encrypts and decrypts a packet number, for a short packet with a short packet number", func() {
		pn := protocol.PacketNumber(0x42)
		b := &bytes.Buffer{}
		Expect(utils.WriteVarIntPacketNumber(b, pn, protocol.PacketNumberLen2)).To(Succeed())
		packet := make([]byte, 2+bob.(*aead).aeadctr.CTRIVSize())
		rand.Read(packet)
		copy(packet[0:2], b.Bytes())
		err := alice.EncryptPacketNumber(packet, protocol.PacketNumberLen2)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet[0:2]).ToNot(Equal(b.Bytes())) // make sure the ciphertext is different from the cleartext
		pnDecrypted, pnLen, err := bob.DecryptPacketNumber(packet)
		Expect(err).ToNot(HaveOccurred())
		Expect(pnLen).To(Equal(protocol.PacketNumberLen2))
		Expect(pnDecrypted).To(Equal(pn))
	})

	It("errors when encrypting for too short packets", func() {
		pn := protocol.PacketNumber(0xbeef42)
		b := &bytes.Buffer{}
		Expect(utils.WriteVarIntPacketNumber(b, pn, protocol.PacketNumberLen4)).To(Succeed())
		packet := make([]byte, 10)
		copy(packet[0:4], b.Bytes())
		err := alice.EncryptPacketNumber(packet, protocol.PacketNumberLen4)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("calculated too small packet number encryption sampling offset"))
	})

	It("errors when decrypting for too short packets", func() {
		packet := make([]byte, 10)
		_, _, err := bob.DecryptPacketNumber(packet)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("calculated too small packet number encryption sampling offset"))
	})
})
