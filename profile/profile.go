// Package profile validates immutable wire profiles and builds fresh uTLS specs.
package profile

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// GREASE is a placeholder, not a fixed on-wire value.
const GREASE uint16 = 0x0a0a

type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}
type Priority struct {
	StreamDep uint32 `json:"stream_dep"`
	Exclusive bool   `json:"exclusive"`
	Weight    uint16 `json:"weight"`
}
type PriorityFrame struct {
	StreamID uint32 `json:"stream_id"`
	Priority
}
type HTTP2Config struct {
	Settings               []Setting       `json:"settings"`
	ConnectionWindowUpdate uint32          `json:"connection_window_update"`
	PseudoHeaderOrder      []string        `json:"pseudo_header_order"`
	HeaderPriority         *Priority       `json:"header_priority,omitempty"`
	InitialPriorities      []PriorityFrame `json:"initial_priorities,omitempty"`
}

type echCipherSuite struct {
	KDFID  uint16 `json:"kdf_id"`
	AEADID uint16 `json:"aead_id"`
}

type extension struct {
	Type             string           `json:"type"`
	Values           []uint16         `json:"values,omitempty"`
	Protocols        []string         `json:"protocols,omitempty"`
	ID               *uint16          `json:"id,omitempty"`
	DataHex          *string          `json:"data_hex,omitempty"`
	AllowOpaque      bool             `json:"allow_opaque,omitempty"`
	AllowUnsupported bool             `json:"allow_unsupported,omitempty"`
	PayloadLengths   []uint16         `json:"payload_lengths,omitempty"`
	PaddingLength    *uint16          `json:"padding_length,omitempty"`
	RecordSizeLimit  *uint16          `json:"record_size_limit,omitempty"`
	ECHCipherSuites  []echCipherSuite `json:"ech_cipher_suites,omitempty"`
}
type tlsConfig struct {
	MinVersion   uint16      `json:"min_version"`
	MaxVersion   uint16      `json:"max_version"`
	CipherSuites []uint16    `json:"cipher_suites"`
	Extensions   []extension `json:"extensions"`
}
type document struct {
	SchemaVersion int         `json:"schema_version"`
	Name          string      `json:"name"`
	HTTPVersion   string      `json:"http_version,omitempty"`
	Notes         []string    `json:"notes,omitempty"`
	TLS           tlsConfig   `json:"tls"`
	HTTP2         HTTP2Config `json:"http2"`
}

// Profile exposes no mutable backing state and is safe to share across goroutines.
type Profile struct {
	doc         document
	hash        string
	limitations []string
}

func LoadFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}
func Load(data []byte) (*Profile, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if _, ok := raw["schema_version"]; !ok {
		if _, ok := raw["tls"]; ok {
			return nil, fmt.Errorf("profile: schema_version is required; for tls.peet.ws captures use ImportPeet(data, allowOpaque)")
		}
	}
	var d document
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("profile: trailing JSON content")
	}
	return compile(d)
}

func compile(d document) (*Profile, error) {
	p := &Profile{doc: d}
	if d.SchemaVersion != 1 {
		return nil, fmt.Errorf("profile: unsupported schema_version %d (expected 1)", d.SchemaVersion)
	}
	if d.Name == "" {
		return nil, fmt.Errorf("profile: name is required")
	}
	if d.HTTPVersion != "" && d.HTTPVersion != "h2" && d.HTTPVersion != "http/1.1" {
		return nil, fmt.Errorf("profile: http_version must be h2 or http/1.1")
	}
	if d.TLS.MinVersion < utls.VersionTLS10 || d.TLS.MaxVersion > utls.VersionTLS13 || d.TLS.MinVersion > d.TLS.MaxVersion {
		return nil, fmt.Errorf("profile: tls version range must be within TLS 1.0..1.3")
	}
	if len(d.TLS.CipherSuites) == 0 || len(d.TLS.CipherSuites) > 32767 {
		return nil, fmt.Errorf("profile: tls.cipher_suites must contain 1..32767 entries")
	}
	knownCiphers := map[uint16]bool{}
	for _, c := range append(utls.CipherSuites(), utls.InsecureCipherSuites()...) {
		knownCiphers[c.ID] = true
	}
	knownCiphers[0x00ff], knownCiphers[0x5600] = true, true // signaling cipher-suite values
	for i, c := range d.TLS.CipherSuites {
		if isGREASE(c) {
			p.doc.TLS.CipherSuites[i] = GREASE
			continue
		}
		if !knownCiphers[c] {
			p.limitations = append(p.limitations, fmt.Sprintf("Cipher suite 0x%04x is advertised only; uTLS cannot negotiate this algorithm if selected by the server.", c))
		}
	}
	if len(d.TLS.Extensions) == 0 {
		return nil, fmt.Errorf("profile: tls.extensions must not be empty")
	}
	seen := map[uint16]bool{}
	greaseCount := 0
	for i, e := range d.TLS.Extensions {
		for j, v := range e.Values {
			if isGREASE(v) {
				p.doc.TLS.Extensions[i].Values[j] = GREASE
			}
		}
		id, err := extensionID(e)
		if err != nil {
			return nil, fmt.Errorf("profile: tls.extensions[%d]: %w", i, err)
		}
		if e.Type == "grease" {
			greaseCount++
			if greaseCount > 2 {
				return nil, fmt.Errorf("profile: uTLS supports at most two GREASE extensions")
			}
		} else {
			if seen[id] {
				return nil, fmt.Errorf("profile: duplicate TLS extension %d", id)
			}
			seen[id] = true
		}
		if err := validateExtension(e); err != nil {
			return nil, fmt.Errorf("profile: tls.extensions[%d] (%s): %w", i, e.Type, err)
		}
		if e.Type == "raw" {
			if id == 51764 {
				p.limitations = append(p.limitations, "TLS trust_anchors extension 51764 uses an explicitly opted-in static capture payload; Trust Anchor IDs certificate selection/retry behavior and dynamic anchor state are not implemented.")
			} else {
				p.limitations = append(p.limitations, fmt.Sprintf("Extension %d uses an explicitly opted-in static payload; its protocol behavior is not implemented.", id))
			}
		}
		if e.Type == "application_settings" || e.Type == "application_settings_new" {
			p.limitations = append(p.limitations, "ALPS negotiation is delegated to uTLS; this prototype does not apply peer HTTP/2 application settings or configure custom client ALPS payloads.")
		}
		if e.Type == "signature_algorithms" || e.Type == "signature_algorithms_cert" || e.Type == "delegated_credentials" {
			for _, v := range e.Values {
				if !isGREASE(v) && !supportedSignature(v) {
					p.limitations = append(p.limitations, fmt.Sprintf("Signature scheme 0x%04x is advertised only; uTLS v1.8.2 cannot verify it if selected by the server.", v))
				}
			}
		}
		if e.Type == "delegated_credentials" || e.Type == "record_size_limit" || e.Type == "channel_id" || e.Type == "channel_id_old" || e.Type == "token_binding" {
			p.limitations = append(p.limitations, fmt.Sprintf("Extension %d (%s) is advertised using uTLS's compatibility builder; its full negotiated protocol behavior is not implemented.", id, e.Type))
		}
		if e.Type == "supported_groups" {
			for _, v := range e.Values {
				if !supportedGroup(v) {
					p.limitations = append(p.limitations, fmt.Sprintf("Named group %d is advertised only; uTLS cannot perform its key exchange if selected by the server.", v))
				}
			}
		}
		if e.Type == "ec_point_formats" {
			for _, v := range e.Values {
				if v != 0 {
					p.limitations = append(p.limitations, fmt.Sprintf("EC point format %d is advertised only; uTLS uses uncompressed EC points.", v))
				}
			}
		}
		if e.Type == "psk_key_exchange_modes" {
			for _, v := range e.Values {
				if v != 1 {
					p.limitations = append(p.limitations, fmt.Sprintf("PSK key exchange mode %d is advertised only; uTLS session resumption uses psk_dhe_ke.", v))
				}
			}
		}
	}
	if p.doc.TLS.MaxVersion == utls.VersionTLS13 && (!seen[43] || !seen[51] || !seen[13]) {
		return nil, fmt.Errorf("profile: TLS 1.3 requires supported_versions, key_share and signature_algorithms extensions")
	}
	for _, e := range p.doc.TLS.Extensions {
		if e.Type == "supported_versions" {
			hasMax := false
			for _, v := range e.Values {
				if isGREASE(v) {
					continue
				}
				if v < p.doc.TLS.MinVersion || v > p.doc.TLS.MaxVersion {
					if v >= 769 && v <= 772 {
						return nil, fmt.Errorf("profile: supported_versions value %d is outside configured TLS version range", v)
					}
					p.limitations = append(p.limitations, fmt.Sprintf("TLS version 0x%04x is advertised only; uTLS cannot negotiate it.", v))
				}
				if v == p.doc.TLS.MaxVersion {
					hasMax = true
				}
			}
			if !hasMax {
				return nil, fmt.Errorf("profile: supported_versions must advertise max_version")
			}
		}
	}
	if seen[51] && !seen[10] {
		return nil, fmt.Errorf("profile: key_share requires supported_groups")
	}
	groups := map[uint16]bool{}
	for _, e := range p.doc.TLS.Extensions {
		if e.Type == "supported_groups" {
			for _, v := range e.Values {
				if isGREASE(v) {
					v = GREASE
				}
				groups[v] = true
			}
		}
	}
	for _, e := range p.doc.TLS.Extensions {
		if e.Type == "key_share" {
			for _, v := range e.Values {
				if isGREASE(v) {
					v = GREASE
				}
				if !groups[v] {
					return nil, fmt.Errorf("profile: key_share group %d is absent from supported_groups", v)
				}
			}
		}
	}
	if p.doc.HTTP2.PseudoHeaderOrder == nil {
		p.doc.HTTP2.PseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}
	}
	if p.HTTPVersion() == "http/1.1" {
		p.limitations = append(p.limitations, "This capture contains HTTP/1.1 metadata rather than HTTP/2 wire settings; if ALPN negotiates h2, the transport uses its default HTTP/2 settings.")
	}
	if len(p.doc.HTTP2.InitialPriorities) != 0 {
		p.limitations = append(p.limitations, "Initial HTTP/2 PRIORITY frames are preserved as profile metadata but are not emitted by this transport; their HTTP/2 fingerprint is not reproduced.")
	}
	if err := validateHTTP2(p.doc.HTTP2); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(p.doc)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	p.hash = hex.EncodeToString(sum[:])
	return p, nil
}

func (p *Profile) Hash() string { return p.hash }
func (p *Profile) Name() string { return p.doc.Name }
func (p *Profile) HTTPVersion() string {
	if p.doc.HTTPVersion == "" {
		return "h2"
	}
	return p.doc.HTTPVersion
}
func (p *Profile) Limitations() []string        { return slices.Clone(p.limitations) }
func (p *Profile) MarshalJSON() ([]byte, error) { return json.Marshal(p.doc) }
func (p *Profile) HTTP2() HTTP2Config {
	c := p.doc.HTTP2
	c.Settings = slices.Clone(c.Settings)
	c.PseudoHeaderOrder = slices.Clone(c.PseudoHeaderOrder)
	c.InitialPriorities = slices.Clone(c.InitialPriorities)
	if c.HeaderPriority != nil {
		v := *c.HeaderPriority
		c.HeaderPriority = &v
	}
	return c
}

// NewClientHelloSpec must be called for every TLS connection. uTLS mutates specs
// during ApplyPreset; caching or sharing these returned objects is unsafe.
func (p *Profile) NewClientHelloSpec() (*utls.ClientHelloSpec, error) {
	return p.NewClientHelloSpecWithOptions(ClientHelloOptions{})
}

// ClientHelloOptions affects only a fresh connection's independently owned spec.
type ClientHelloOptions struct {
	RandomJA3  bool
	ForceHTTP1 bool
}

func (p *Profile) NewClientHelloSpecWithOptions(options ClientHelloOptions) (*utls.ClientHelloSpec, error) {
	s := &utls.ClientHelloSpec{TLSVersMin: p.doc.TLS.MinVersion, TLSVersMax: p.doc.TLS.MaxVersion, CipherSuites: slices.Clone(p.doc.TLS.CipherSuites), CompressionMethods: []byte{0}}
	forceHTTP1 := options.ForceHTTP1
	for _, e := range p.doc.TLS.Extensions {
		if forceHTTP1 && (e.Type == "application_settings" || e.Type == "application_settings_new") {
			continue
		}
		if forceHTTP1 && (e.Type == "alpn" || e.Type == "npn") {
			e.Protocols = []string{"http/1.1"}
		}
		ext, err := buildExtension(e)
		if err != nil {
			return nil, err
		}
		s.Extensions = append(s.Extensions, ext)
	}
	if options.RandomJA3 {
		// Chrome pins GREASE, padding and PSK positions. Shuffle only movable
		// positions with crypto/rand; never touch the immutable profile's arrays.
		var positions []int
		for i, ext := range s.Extensions {
			switch ext.(type) {
			case *utls.UtlsGREASEExtension, *utls.UtlsPaddingExtension, utls.PreSharedKeyExtension:
				continue
			}
			positions = append(positions, i)
		}
		for i := len(positions) - 1; i > 0; i-- {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
			if err != nil {
				return nil, fmt.Errorf("profile: shuffle extensions: %w", err)
			}
			a, b := positions[i], positions[int(n.Int64())]
			s.Extensions[a], s.Extensions[b] = s.Extensions[b], s.Extensions[a]
		}
	}
	return s, nil
}

func extensionID(e extension) (uint16, error) {
	ids := map[string]uint16{"server_name": 0, "status_request": 5, "supported_groups": 10, "ec_point_formats": 11, "signature_algorithms": 13, "alpn": 16, "status_request_v2": 17, "sct": 18, "padding": 21, "extended_master_secret": 23, "token_binding": 24, "compress_certificate": 27, "record_size_limit": 28, "delegated_credentials": 34, "session_ticket": 35, "supported_versions": 43, "psk_key_exchange_modes": 45, "signature_algorithms_cert": 50, "key_share": 51, "npn": 13172, "application_settings": 17513, "application_settings_new": 17613, "channel_id_old": 30031, "channel_id": 30032, "grease_ech": 65037, "renegotiation_info": 65281, "grease": GREASE}
	if id, ok := ids[e.Type]; ok {
		return id, nil
	}
	if e.Type == "raw" && e.ID != nil {
		return *e.ID, nil
	}
	return 0, fmt.Errorf("unsupported extension type %q", e.Type)
}
func validateExtension(e extension) error {
	usesValues := slices.Contains([]string{"supported_groups", "ec_point_formats", "signature_algorithms", "signature_algorithms_cert", "delegated_credentials", "token_binding", "compress_certificate", "supported_versions", "psk_key_exchange_modes", "key_share"}, e.Type)
	usesProtocols := slices.Contains([]string{"alpn", "npn", "application_settings", "application_settings_new"}, e.Type)
	if !usesValues && e.Values != nil {
		return fmt.Errorf("values is not valid for this extension")
	}
	if !usesProtocols && e.Protocols != nil {
		return fmt.Errorf("protocols is not valid for this extension")
	}
	if e.Type != "raw" && (e.ID != nil || e.DataHex != nil || e.AllowOpaque) {
		return fmt.Errorf("id, data_hex and allow_opaque are only valid for raw extensions")
	}
	if !slices.Contains([]string{"signature_algorithms", "signature_algorithms_cert", "delegated_credentials"}, e.Type) && e.AllowUnsupported {
		return fmt.Errorf("allow_unsupported is only valid for signature algorithm lists")
	}
	if e.Type != "grease_ech" && (e.PayloadLengths != nil || e.ECHCipherSuites != nil) {
		return fmt.Errorf("ECH shape fields are only valid for grease_ech")
	}
	if (e.PaddingLength != nil) != (e.Type == "padding") {
		return fmt.Errorf("padding requires padding_length, which is invalid on other extensions")
	}
	if (e.RecordSizeLimit != nil) != (e.Type == "record_size_limit") {
		return fmt.Errorf("record_size_limit requires a record_size_limit value, which is invalid on other extensions")
	}
	if e.RecordSizeLimit != nil && (*e.RecordSizeLimit < 64 || *e.RecordSizeLimit > 16385) {
		return fmt.Errorf("record_size_limit must be 64..16385")
	}
	if usesValues {
		max := 32765
		if e.Type == "ec_point_formats" || e.Type == "psk_key_exchange_modes" {
			max = 255
		}
		if e.Type == "supported_versions" || e.Type == "compress_certificate" {
			max = 127
		}
		if len(e.Values) == 0 || len(e.Values) > max {
			return fmt.Errorf("values requires 1..%d entries", max)
		}
		if e.Type == "token_binding" && (len(e.Values) < 3 || len(e.Values) > 257) {
			return fmt.Errorf("token_binding values require version major/minor and 1..255 key parameters")
		}
		seenValues := map[uint16]bool{}
		hybridKeyShares := 0
		realKeyShares := 0
		for _, v := range e.Values {
			key := v
			if isGREASE(key) {
				key = GREASE
			}
			if seenValues[key] && (e.Type == "key_share" || e.Type == "supported_versions" || e.Type == "supported_groups") {
				return fmt.Errorf("duplicate value %d", key)
			}
			seenValues[key] = true
			if e.Type == "key_share" {
				if !isGREASE(v) {
					realKeyShares++
				}
				if v == 4588 || v == 25497 {
					hybridKeyShares++
				}
				if hybridKeyShares > 1 {
					return fmt.Errorf("uTLS supports only one hybrid key share private state per connection")
				}
			}
			switch e.Type {
			case "token_binding":
				if v > 255 {
					return fmt.Errorf("token_binding values must fit uint8")
				}
			case "key_share":
				if !supportedGroup(v) {
					return fmt.Errorf("unsupported key exchange group %d", v)
				}
			case "ec_point_formats":
				if v > 255 {
					return fmt.Errorf("EC point formats must fit uint8")
				}
			case "signature_algorithms", "signature_algorithms_cert", "delegated_credentials":
				if !isGREASE(v) && !supportedSignature(v) && !e.AllowUnsupported {
					return fmt.Errorf("signature scheme 0x%04x is not implemented; allow_unsupported=true explicitly permits advertisement only", v)
				}
			case "compress_certificate":
				if v < 1 || v > 3 {
					return fmt.Errorf("unsupported certificate compression algorithm %d", v)
				}
			case "psk_key_exchange_modes":
				if v > 255 {
					return fmt.Errorf("PSK key exchange modes must fit uint8")
				}
			}
		}
		if e.Type == "key_share" && realKeyShares == 0 {
			return fmt.Errorf("key_share requires at least one non-GREASE group")
		}
	}
	if usesProtocols {
		if len(e.Protocols) == 0 {
			return fmt.Errorf("protocols must not be empty")
		}
		size := 0
		for _, s := range e.Protocols {
			if len(s) == 0 || len(s) > 255 {
				return fmt.Errorf("protocol names require 1..255 bytes")
			}
			size += len(s) + 1
		}
		if size > 65533 {
			return fmt.Errorf("protocol list is too large")
		}
	}
	if e.Type == "grease_ech" {
		for _, suite := range e.ECHCipherSuites {
			if suite.KDFID < 1 || suite.KDFID > 3 || suite.AEADID < 1 || suite.AEADID > 3 {
				return fmt.Errorf("unsupported GREASE ECH HPKE shape")
			}
		}
		for _, n := range e.PayloadLengths {
			if n == 0 || n > 65000 {
				return fmt.Errorf("ECH payload length must be 1..65000")
			}
		}
	}
	if e.Type == "raw" {
		if !e.AllowOpaque || e.DataHex == nil {
			return fmt.Errorf("raw requires allow_opaque=true and data_hex")
		}
		if e.ID == nil {
			return fmt.Errorf("raw requires an extension id")
		}
		// Session secrets and typed protocol state may never escape validation by
		// being labelled raw. Other explicit static payloads are advertisement-only.
		if rawForbidden(*e.ID) {
			return fmt.Errorf("extension %d requires a typed builder or contains dynamic handshake/session state; raw replay is forbidden", *e.ID)
		}
		b, err := hex.DecodeString(*e.DataHex)
		if err != nil {
			return fmt.Errorf("invalid data_hex: %w", err)
		}
		if len(b) > 65535 {
			return fmt.Errorf("raw extension payload is too large")
		}
	}
	return nil
}
func buildExtension(e extension) (utls.TLSExtension, error) {
	v := slices.Clone(e.Values)
	for i, n := range v {
		if isGREASE(n) {
			v[i] = GREASE
		}
	}
	switch e.Type {
	case "server_name":
		return &utls.SNIExtension{}, nil
	case "status_request":
		return &utls.StatusRequestExtension{}, nil
	case "status_request_v2":
		return &utls.StatusRequestV2Extension{}, nil
	case "padding":
		return &utls.UtlsPaddingExtension{PaddingLen: int(*e.PaddingLength), WillPad: true}, nil
	case "record_size_limit":
		return &utls.FakeRecordSizeLimitExtension{Limit: *e.RecordSizeLimit}, nil
	case "token_binding":
		parameters := make([]uint8, len(v)-2)
		for i, n := range v[2:] {
			parameters[i] = uint8(n)
		}
		return &utls.FakeTokenBindingExtension{MajorVersion: uint8(v[0]), MinorVersion: uint8(v[1]), KeyParameters: parameters}, nil
	case "channel_id", "channel_id_old":
		return &utls.FakeChannelIDExtension{OldExtensionID: e.Type == "channel_id_old"}, nil
	case "npn":
		return &utls.NPNExtension{NextProtos: slices.Clone(e.Protocols)}, nil
	case "session_ticket":
		return &utls.SessionTicketExtension{}, nil
	case "sct":
		return &utls.SCTExtension{}, nil
	case "extended_master_secret":
		return &utls.ExtendedMasterSecretExtension{}, nil
	case "renegotiation_info":
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}, nil
	case "grease":
		return &utls.UtlsGREASEExtension{}, nil
	case "supported_groups":
		x := make([]utls.CurveID, len(v))
		for i, n := range v {
			x[i] = utls.CurveID(n)
		}
		return &utls.SupportedCurvesExtension{Curves: x}, nil
	case "ec_point_formats":
		x := make([]byte, len(v))
		for i, n := range v {
			x[i] = byte(n)
		}
		return &utls.SupportedPointsExtension{SupportedPoints: x}, nil
	case "signature_algorithms", "signature_algorithms_cert", "delegated_credentials":
		x := make([]utls.SignatureScheme, len(v))
		for i, n := range v {
			if isGREASE(n) {
				var b [1]byte
				if _, err := rand.Read(b[:]); err != nil {
					return nil, err
				}
				n = uint16(b[0]&0xf0 | 0x0a)
				n |= n << 8
			}
			x[i] = utls.SignatureScheme(n)
		}
		if e.Type == "signature_algorithms_cert" {
			return &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: x}, nil
		}
		if e.Type == "delegated_credentials" {
			return &utls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: x}, nil
		}
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: x}, nil
	case "alpn":
		return &utls.ALPNExtension{AlpnProtocols: slices.Clone(e.Protocols)}, nil
	case "application_settings":
		return &utls.ApplicationSettingsExtension{SupportedProtocols: slices.Clone(e.Protocols)}, nil
	case "application_settings_new":
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: slices.Clone(e.Protocols)}, nil
	case "supported_versions":
		return &utls.SupportedVersionsExtension{Versions: v}, nil
	case "key_share":
		x := make([]utls.KeyShare, len(v))
		for i, n := range v {
			x[i].Group = utls.CurveID(n)
			if isGREASE(n) {
				x[i].Data = []byte{0}
			}
		}
		return &utls.KeyShareExtension{KeyShares: x}, nil
	case "psk_key_exchange_modes":
		x := make([]byte, len(v))
		for i, n := range v {
			x[i] = byte(n)
		}
		return &utls.PSKKeyExchangeModesExtension{Modes: x}, nil
	case "compress_certificate":
		x := make([]utls.CertCompressionAlgo, len(v))
		for i, n := range v {
			x[i] = utls.CertCompressionAlgo(n)
		}
		return &utls.UtlsCompressCertExtension{Algorithms: x}, nil
	case "grease_ech":
		x := utls.BoringGREASEECH()
		if e.PayloadLengths != nil {
			x.CandidatePayloadLens = slices.Clone(e.PayloadLengths)
		}
		if e.ECHCipherSuites != nil {
			x.CandidateCipherSuites = make([]utls.HPKESymmetricCipherSuite, len(e.ECHCipherSuites))
			for i, suite := range e.ECHCipherSuites {
				x.CandidateCipherSuites[i] = utls.HPKESymmetricCipherSuite{KdfId: suite.KDFID, AeadId: suite.AEADID}
			}
		}
		return x, nil
	case "raw":
		b, err := hex.DecodeString(*e.DataHex)
		return &utls.GenericExtension{Id: *e.ID, Data: b}, err
	}
	return nil, fmt.Errorf("unsupported extension %q", e.Type)
}
func rawForbidden(id uint16) bool {
	return isGREASE(id) || slices.Contains([]uint16{0, 5, 10, 11, 13, 16, 17, 18, 21, 23, 24, 27, 28, 34, 35, 41, 42, 43, 44, 45, 50, 51, 13172, 17513, 17613, 30031, 30032, 65037, 65281, 65486}, id)
}
func isGREASE(v uint16) bool { return byte(v) == byte(v>>8) && v&0x0f0f == 0x0a0a }
func supportedGroup(v uint16) bool {
	return isGREASE(v) || slices.Contains([]uint16{23, 24, 25, 29, 4588, 25497}, v)
}
func supportedSignature(v uint16) bool {
	return slices.Contains([]uint16{0x0201, 0x0203, 0x0401, 0x0501, 0x0601, 0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0603, 0x0807}, v)
}
func validateHTTP2(c HTTP2Config) error {
	for _, p := range c.InitialPriorities {
		if p.StreamID == 0 || p.StreamID > 0x7fffffff || p.StreamDep > 0x7fffffff || p.StreamID == p.StreamDep || p.Weight < 1 || p.Weight > 256 {
			return fmt.Errorf("profile: invalid initial HTTP/2 PRIORITY frame")
		}
	}
	if c.ConnectionWindowUpdate > 0x7fffffff-65535 {
		return fmt.Errorf("profile: connection window would exceed 2^31-1")
	}
	seen := map[uint16]bool{}
	for _, s := range c.Settings {
		if seen[s.ID] {
			return fmt.Errorf("profile: duplicate HTTP/2 setting %d", s.ID)
		}
		seen[s.ID] = true
		switch s.ID {
		case 2, 8, 9:
			if s.Value > 1 {
				return fmt.Errorf("profile: setting %d requires value 0 or 1", s.ID)
			}
		case 4:
			if s.Value > 0x7fffffff {
				return fmt.Errorf("profile: INITIAL_WINDOW_SIZE exceeds 2^31-1")
			}
		case 5:
			if s.Value < 16384 || s.Value > 16777215 {
				return fmt.Errorf("profile: invalid MAX_FRAME_SIZE")
			}
		}
	}
	required := map[string]bool{":method": false, ":authority": false, ":scheme": false, ":path": false}
	if len(c.PseudoHeaderOrder) != 4 {
		return fmt.Errorf("profile: pseudo_header_order must contain the four request pseudo headers")
	}
	for _, s := range c.PseudoHeaderOrder {
		used, ok := required[s]
		if !ok || used {
			return fmt.Errorf("profile: invalid or duplicate pseudo header %q", s)
		}
		required[s] = true
	}
	if c.HeaderPriority != nil && (c.HeaderPriority.Weight < 1 || c.HeaderPriority.Weight > 256 || c.HeaderPriority.StreamDep > 0x7fffffff) {
		return fmt.Errorf("profile: header_priority requires weight 1..256 and a 31-bit stream dependency")
	}
	return nil
}
