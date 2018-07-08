package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type aesCTR struct {
	encrypter cipher.Block
	decrypter cipher.Block
}

var _ ctr = &aesCTR{}

func newCTR(myKey, otherKey []byte) (ctr, error) {
	encrypter, err := aes.NewCipher(myKey)
	if err != nil {
		return nil, err
	}
	decrypter, err := aes.NewCipher(otherKey)
	if err != nil {
		return nil, err
	}
	return &aesCTR{
		encrypter: encrypter,
		decrypter: decrypter,
	}, nil
}

func (c *aesCTR) Encrypt(plain, iv []byte) error {
	if len(iv) != c.encrypter.BlockSize() {
		return errors.New("wrong IV size")
	}
	ctr := cipher.NewCTR(c.encrypter, iv)
	ctr.XORKeyStream(plain, plain)
	return nil
}

func (c *aesCTR) Decrypt(ciphertext, iv []byte) error {
	if len(iv) != c.decrypter.BlockSize() {
		return errors.New("wrong IV size")
	}
	ctr := cipher.NewCTR(c.decrypter, iv)
	ctr.XORKeyStream(ciphertext, ciphertext)
	return nil
}

func (c *aesCTR) CTRIVSize() int {
	return c.encrypter.BlockSize()
}
