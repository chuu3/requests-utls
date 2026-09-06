package http2

import (
	"fmt"
	"math"
)

// WireProfile specifies the client's connection preface and request pseudo-header
// order. Configure it before using Transport, then leave it immutable. Settings
// are emitted exactly in slice order. Omitted settings use HTTP/2 protocol
// defaults, whereas explicit zero values retain their protocol meaning.
type WireProfile struct {
	Settings               []Setting
	ConnectionWindowUpdate uint32
	PseudoHeaderOrder      []string
	HeaderPriority         *PriorityParam
}

// Validate rejects profiles the client cannot implement faithfully.
func (p *WireProfile) Validate() error {
	if p == nil {
		return nil
	}
	if len(p.Settings) > initialMaxFrameSize/6 {
		return fmt.Errorf("http2: initial SETTINGS payload exceeds the peer's default frame limit")
	}
	if p.ConnectionWindowUpdate > math.MaxInt32-initialWindowSize {
		return fmt.Errorf("http2: connection window update exceeds the 31-bit receive window")
	}
	seen := make(map[SettingID]bool, len(p.Settings))
	for i, s := range p.Settings {
		if seen[s.ID] {
			return fmt.Errorf("http2: settings[%d]: duplicate setting %d", i, s.ID)
		}
		seen[s.ID] = true
		if err := s.Valid(); err != nil {
			return fmt.Errorf("http2: settings[%d] (%s): %w", i, s.ID, err)
		}
		// SETTINGS_NO_RFC7540_PRIORITIES (RFC 9218).
		if s.ID == SettingNoRFC7540Priorities && s.Val > 1 {
			return fmt.Errorf("http2: settings[%d]: NO_RFC7540_PRIORITIES must be 0 or 1", i)
		}
	}
	if len(p.PseudoHeaderOrder) != 0 {
		want := map[string]bool{":method": false, ":authority": false, ":scheme": false, ":path": false}
		if len(p.PseudoHeaderOrder) != len(want) {
			return fmt.Errorf("http2: pseudo-header order must contain :method, :authority, :scheme and :path exactly once")
		}
		for _, name := range p.PseudoHeaderOrder {
			duplicate, known := want[name]
			if !known || duplicate {
				return fmt.Errorf("http2: invalid or duplicate pseudo-header %q", name)
			}
			want[name] = true
		}
	}
	if p.HeaderPriority != nil && p.HeaderPriority.StreamDep > math.MaxInt32 {
		return fmt.Errorf("http2: priority dependency must be a 31-bit stream ID")
	}
	return nil
}

func (p *WireProfile) clone() *WireProfile {
	if p == nil {
		return nil
	}
	q := *p
	q.Settings = append([]Setting(nil), p.Settings...)
	q.PseudoHeaderOrder = append([]string(nil), p.PseudoHeaderOrder...)
	if p.HeaderPriority != nil {
		priority := *p.HeaderPriority
		q.HeaderPriority = &priority
	}
	return &q
}

// applyWireConfig is deliberately called after configFromTransport so upstream's
// "zero means default" normalization cannot replace explicit wire zero values.
func (p *WireProfile) applyWireConfig(conf *http2Config) {
	conf.MaxDecoderHeaderTableSize = initialHeaderTableSize
	conf.MaxReadFrameSize = initialMaxFrameSize
	conf.MaxUploadBufferPerStream = initialWindowSize
	conf.MaxUploadBufferPerConnection = int32(p.ConnectionWindowUpdate)
	for _, s := range p.Settings {
		switch s.ID {
		case SettingHeaderTableSize:
			conf.MaxDecoderHeaderTableSize = s.Val
		case SettingInitialWindowSize:
			conf.MaxUploadBufferPerStream = int32(s.Val)
		case SettingMaxFrameSize:
			conf.MaxReadFrameSize = s.Val
		}
	}
}
