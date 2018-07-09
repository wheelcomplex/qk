package crypto

type aeadCTR struct {
	AEAD
	ctr
}

var _ AEADCTR = &aeadCTR{}

func NewAESAEADCTR(otherKey, myKey, otherIV, myIV, otherPNKey, myPNKey []byte) (AEADCTR, error) {
	aead, err := newAEADAESGCM(otherKey, myKey, otherIV, myIV)
	if err != nil {
		return nil, err
	}
	ctr, err := newCTR(myPNKey, otherPNKey)
	if err != nil {
		return nil, err
	}
	return &aeadCTR{
		AEAD: aead,
		ctr:  ctr,
	}, nil
}
