package wire

import (
	"bytes"
	"errors"
	"math"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// An ApplicationCloseFrame is an APPLICATION_CLOSE_FRAME
type ApplicationCloseFrame struct {
	ErrorCode    qerr.ErrorCode
	ReasonPhrase string
}

// ParseApplicationCloseFrame parses an APPLICATION_CLOSE frame
func ParseApplicationCloseFrame(r *bytes.Reader, version protocol.VersionNumber) (*ApplicationCloseFrame, error) {
	ccf, err := ParseConnectionCloseFrame(r, version)
	if err != nil {
		return nil, err
	}
	return &ApplicationCloseFrame{
		ErrorCode:    ccf.ErrorCode,
		ReasonPhrase: ccf.ReasonPhrase,
	}, nil
}

// MinLength of a written frame
func (f *ApplicationCloseFrame) MinLength(_ protocol.VersionNumber) protocol.ByteCount {
	return 1 + 2 + utils.VarIntLen(uint64(len(f.ReasonPhrase))) + protocol.ByteCount(len(f.ReasonPhrase))
}

func (f *ApplicationCloseFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0x03)

	if len(f.ReasonPhrase) > math.MaxUint16 {
		return errors.New("ConnectionFrame: ReasonPhrase too long")
	}
	utils.BigEndian.WriteUint16(b, uint16(f.ErrorCode))
	utils.WriteVarInt(b, uint64(len(f.ReasonPhrase)))
	b.WriteString(f.ReasonPhrase)
	return nil
}
