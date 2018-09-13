package mocks

//go:generate sh -c "../mockgen_internal.sh mocks tls_extension_handler.go github.com/wheelcomplex/qk/internal/handshake TLSExtensionHandler"
//go:generate sh -c "../mockgen_internal.sh mocks stream_flow_controller.go github.com/wheelcomplex/qk/internal/flowcontrol StreamFlowController"
//go:generate sh -c "../mockgen_internal.sh mockackhandler ackhandler/sent_packet_handler.go github.com/wheelcomplex/qk/internal/ackhandler SentPacketHandler"
//go:generate sh -c "../mockgen_internal.sh mockackhandler ackhandler/received_packet_handler.go github.com/wheelcomplex/qk/internal/ackhandler ReceivedPacketHandler"
//go:generate sh -c "../mockgen_internal.sh mocks congestion.go github.com/wheelcomplex/qk/internal/congestion SendAlgorithm"
//go:generate sh -c "../mockgen_internal.sh mocks connection_flow_controller.go github.com/wheelcomplex/qk/internal/flowcontrol ConnectionFlowController"
//go:generate sh -c "../mockgen_internal.sh mockcrypto crypto/aead.go github.com/wheelcomplex/qk/internal/crypto AEAD"
