package ackhandler

import "github.com/enetx/quic-go/internal/congestion"

// ClientSendConfig separates wire/loss bookkeeping from sender arithmetic.
// Server constructors ignore these application-selected client mechanisms.
type ClientSendConfig struct {
	DisablePacketNumberSkipping   bool
	Congestion                    congestion.SenderConfig
	SeparatePacketNumberSpaces    bool
	PersistentCongestionThreshold uint32
}

func (h *sentPacketHandler) OnApplicationLimited() {
	if sender, ok := h.congestion.(congestion.ApplicationLimitedHandler); ok {
		sender.OnApplicationLimited()
	}
}
