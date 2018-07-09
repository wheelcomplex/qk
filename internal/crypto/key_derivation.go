package crypto

import (
	"crypto"
	"encoding/binary"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const (
	clientExporterLabel = "EXPORTER-QUIC client 1rtt"
	serverExporterLabel = "EXPORTER-QUIC server 1rtt"
)

// A TLSExporter gets the negotiated ciphersuite and computes exporter
type TLSExporter interface {
	GetCipherSuite() mint.CipherSuiteParams
	ComputeExporter(label string, context []byte, keyLength int) ([]byte, error)
}

func qhkdfExpand(secret []byte, label string, length int) []byte {
	qlabel := make([]byte, 2+1+5+len(label))
	binary.BigEndian.PutUint16(qlabel[0:2], uint16(length))
	qlabel[2] = uint8(5 + len(label))
	copy(qlabel[3:], []byte("QUIC "+label))
	return mint.HkdfExpand(crypto.SHA256, secret, qlabel, length)
}

// DeriveAESKeys derives the AES keys and creates a matching AES-GCM AEAD instance
func DeriveAESKeys(tls TLSExporter, pers protocol.Perspective) (AEADCTR, error) {
	var myLabel, otherLabel string
	if pers == protocol.PerspectiveClient {
		myLabel = clientExporterLabel
		otherLabel = serverExporterLabel
	} else {
		myLabel = serverExporterLabel
		otherLabel = clientExporterLabel
	}
	myKey, myIV, myPNKey, err := computeKeyAndIV(tls, myLabel)
	if err != nil {
		return nil, err
	}
	otherKey, otherIV, otherPNKey, err := computeKeyAndIV(tls, otherLabel)
	if err != nil {
		return nil, err
	}
	return NewAESAEADCTR(otherKey, myKey, otherIV, myIV, otherPNKey, myPNKey)
}

func computeKeyAndIV(tls TLSExporter, label string) (key, iv, pnkey []byte, err error) {
	cs := tls.GetCipherSuite()
	secret, err := tls.ComputeExporter(label, nil, cs.Hash.Size())
	if err != nil {
		return nil, nil, nil, err
	}
	key = qhkdfExpand(secret, "key", cs.KeyLen)
	iv = qhkdfExpand(secret, "iv", cs.IvLen)
	pnkey = qhkdfExpand(secret, "pn", cs.KeyLen)
	return key, iv, pnkey, nil
}
