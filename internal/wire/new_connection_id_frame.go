package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A NewConnectionIDFrame is a NEW_CONNECTION_ID frame
type NewConnectionIDFrame struct {
	Sequence            uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken [16]byte
}

// ParseNewConnectionIDFrame parses a NEW_CONNECTION_ID frame
func ParseNewConnectionIDFrame(r *bytes.Reader, _ protocol.VersionNumber) (*NewConnectionIDFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	sequence, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	connID, err := utils.BigEndian.ReadUint64(r)
	if err != nil {
		return nil, err
	}
	token := make([]byte, 16)
	if _, err = io.ReadFull(r, token); err != nil {
		return nil, io.EOF // io.ReadFull return io.ErrUnexpectedEOF when it encounters an EOF
	}
	frame := &NewConnectionIDFrame{
		Sequence:     sequence,
		ConnectionID: protocol.ConnectionID(connID),
	}
	copy(frame.StatelessResetToken[:], token)
	return frame, nil
}

func (f *NewConnectionIDFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0x0b)
	utils.WriteVarInt(b, f.Sequence)
	utils.BigEndian.WriteUint64(b, uint64(f.ConnectionID))
	b.Write(f.StatelessResetToken[:])
	return nil
}

// MinLength of a written frame
func (f *NewConnectionIDFrame) MinLength(_ protocol.VersionNumber) protocol.ByteCount {
	return 1 + utils.VarIntLen(f.Sequence) + 8 + 16
}
