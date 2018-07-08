package crypto

import (
	"crypto/rand"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AES-CTR", func() {
	var (
		alice, bob           ctr
		keyAlice, keyBob, iv []byte
	)

	// 16 bytes for TLS_AES_128_GCM_SHA256
	// 32 bytes for TLS_AES_256_GCM_SHA384
	for _, ks := range []int{16, 32} {
		keySize := ks

		Context(fmt.Sprintf("with %d byte keys", keySize), func() {
			BeforeEach(func() {
				keyAlice = make([]byte, keySize)
				keyBob = make([]byte, keySize)
				iv = make([]byte, 16)
				rand.Reader.Read(keyAlice)
				rand.Reader.Read(keyBob)
				rand.Reader.Read(iv)
				var err error
				alice, err = newCTR(keyAlice, keyBob)
				Expect(err).ToNot(HaveOccurred())
				bob, err = newCTR(keyBob, keyAlice)
				Expect(err).ToNot(HaveOccurred())
			})

			It("encrypts and decrypts", func() {
				data := []byte("foobar")
				Expect(alice.Encrypt(data, iv)).To(Succeed())
				Expect(data).ToNot(Equal([]byte("foobar")))
				Expect(bob.Decrypt(data, iv)).To(Succeed())
				Expect(data).To(Equal([]byte("foobar")))
			})

			It("encrypts and decrypts reverse", func() {
				data := []byte("foobar")
				Expect(bob.Encrypt(data, iv)).To(Succeed())
				Expect(data).ToNot(Equal([]byte("foobar")))
				Expect(alice.Decrypt(data, iv)).To(Succeed())
				Expect(data).To(Equal([]byte("foobar")))
			})

			It("errors when encrypting with a wrong size IV", func() {
				Expect(alice.Encrypt([]byte("foobar"), iv[:15])).To(MatchError("wrong IV size"))
			})

			It("errors when decrypting with a wrong size IV", func() {
				Expect(alice.Decrypt([]byte("foobar"), iv[:15])).To(MatchError("wrong IV size"))
			})

			It("has the right IV size", func() {
				Expect(alice.CTRIVSize()).To(Equal(16))
				Expect(bob.CTRIVSize()).To(Equal(16))
			})
		})
	}

	It("errors when an invalid key size is used for the own key", func() {
		_, err := newCTR(make([]byte, 17), make([]byte, 16))
		Expect(err).To(MatchError("crypto/aes: invalid key size 17"))
	})

	It("errors when an invalid key size is used for the other key", func() {
		_, err := newCTR(make([]byte, 16), make([]byte, 17))
		Expect(err).To(MatchError("crypto/aes: invalid key size 17"))
	})
})
