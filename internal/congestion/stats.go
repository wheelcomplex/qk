package congestion

import "github.com/wheelcomplex/qk/internal/protocol"

type connectionStats struct {
	slowstartPacketsLost protocol.PacketNumber
	slowstartBytesLost   protocol.ByteCount
}
