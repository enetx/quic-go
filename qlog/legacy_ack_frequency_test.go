package qlog

import (
	"testing"
	"time"
)

func TestLegacyAckFrequencyFrame(t *testing.T) {
	check(t, &LegacyAckFrequencyFrame{SequenceNumber: 1, AckElicitingThreshold: 8, RequestMaxAckDelay: 5 * time.Millisecond, IgnoreOrder: true}, `{"frame_type":"ack_frequency","sequence_number":1,"ack_eliciting_threshold":8,"request_max_ack_delay":5,"ignore_order":true}`)
}
