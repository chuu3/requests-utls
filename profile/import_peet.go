package profile

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/refraction-networking/utls/dicttls"
)

// ImportPeet converts a tls.peet.ws /api/all capture to a native profile.
// Capture metadata, request header values, randoms, session IDs, SNI, tickets,
// key-share bytes and ECH ciphertext are never stored. allowOpaque explicitly
// permits static raw extensions and advertisement of unsupported signature IDs;
// both are reported by Limitations and encoded as explicit native opt-ins.
func ImportPeet(data []byte, allowOpaque bool) (*Profile, error) {
	var c struct {
		HTTPVersion string `json:"http_version"`
		TLS         struct {
			Ciphers    []json.RawMessage `json:"ciphers"`
			Extensions []json.RawMessage `json:"extensions"`
			PeetPrint  string            `json:"peetprint"`
			JA4Raw     string            `json:"ja4_r"`
		} `json:"tls"`
		HTTP2 struct {
			SentFrames []struct {
				Type      string   `json:"frame_type"`
				StreamID  uint32   `json:"stream_id"`
				Settings  []string `json:"settings"`
				Increment uint32   `json:"increment"`
				Headers   []string `json:"headers"`
				Priority  *struct {
					Weight    uint16 `json:"weight"`
					DependsOn uint32 `json:"depends_on"`
					Exclusive int    `json:"exclusive"`
				} `json:"priority"`
			} `json:"sent_frames"`
		} `json:"http2"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("peet import: %w", err)
	}
	protocol := strings.ToLower(c.HTTPVersion)
	if protocol != "h2" && protocol != "http/1.1" {
		return nil, fmt.Errorf("peet import: expected http_version h2 or HTTP/1.1, got %q", c.HTTPVersion)
	}
	// Reject resumed captures before other validation so errors always explain
	// the unsupported secret state instead of suggesting opaque replay.
	for _, raw := range c.TLS.Extensions {
		var marker struct {
			Name string `json:"name"`
			Data string `json:"data"`
		}
		if json.Unmarshal(raw, &marker) == nil {
			id, err := parseNumericName(marker.Name)
			if err == nil && (id == 41 || id == 42 || id == 44 || (id == 35 && marker.Data != "")) {
				return nil, fmt.Errorf("peet import: resumed/retry handshake capture contains extension %d; captured PSK, early data, tickets and retry cookies are not importable; provide a fresh full-handshake capture", id)
			}
		}
	}
	d := document{SchemaVersion: 1, Name: "imported-peet-profile", HTTPVersion: protocol, TLS: tlsConfig{MinVersion: 771, MaxVersion: 771}, Notes: []string{
		"Imported from a single tls.peet.ws capture. Extension order is fixed to that sample, not a browser's complete randomized ordering policy.",
		"IP addresses, capture metadata, request header values, SNI, randoms, session IDs, key material and ECH ciphertext were removed; dynamic TLS values are generated per connection.",
		"GREASE extension bodies follow uTLS's BoringSSL behavior: first empty, second one zero byte; the capture does not expose their lengths.",
	}}
	for i, raw := range c.TLS.Ciphers {
		id, err := parseCipher(raw)
		if err != nil {
			return nil, fmt.Errorf("peet import: ciphers[%d]: %w", i, err)
		}
		d.TLS.CipherSuites = append(d.TLS.CipherSuites, id)
	}
	for i, raw := range c.TLS.Extensions {
		e, err := importExtension(raw, allowOpaque, &signatureReference{PeetPrint: c.TLS.PeetPrint, JA4Raw: c.TLS.JA4Raw})
		if err != nil {
			return nil, fmt.Errorf("peet import: tls.extensions[%d]: %w", i, err)
		}
		d.TLS.Extensions = append(d.TLS.Extensions, e)
		if e.Type == "supported_versions" {
			var versions []uint16
			for _, v := range e.Values {
				if v >= 769 && v <= 772 {
					versions = append(versions, v)
				}
			}
			if len(versions) > 0 {
				d.TLS.MinVersion, d.TLS.MaxVersion = slices.Min(versions), slices.Max(versions)
			}
		}
	}
	if protocol == "http/1.1" {
		return compile(d)
	}
	settingsSeen, headersSeen, windowSeen := false, false, false
	for i, f := range c.HTTP2.SentFrames {
		switch f.Type {
		case "SETTINGS":
			if settingsSeen || headersSeen {
				return nil, fmt.Errorf("peet import: multiple or late SETTINGS frames are not supported")
			}
			settingsSeen = true
			for _, s := range f.Settings {
				item, err := parseSetting(s)
				if err != nil {
					return nil, err
				}
				d.HTTP2.Settings = append(d.HTTP2.Settings, item)
			}
		case "WINDOW_UPDATE":
			if !settingsSeen || f.StreamID != 0 || headersSeen || windowSeen {
				return nil, fmt.Errorf("peet import: only one initial connection WINDOW_UPDATE is supported")
			}
			windowSeen = true
			d.HTTP2.ConnectionWindowUpdate = f.Increment
			if f.Increment == 0 {
				return nil, fmt.Errorf("peet import: WINDOW_UPDATE increment must be positive")
			}
		case "HEADERS":
			if headersSeen {
				return nil, fmt.Errorf("peet import: multiple HEADERS frames require a single-request capture")
			}
			headersSeen = true
			for _, h := range f.Headers {
				if strings.HasPrefix(h, ":") {
					j := strings.Index(h[1:], ":")
					if j < 0 {
						return nil, fmt.Errorf("peet import: malformed pseudo header %q", h)
					}
					d.HTTP2.PseudoHeaderOrder = append(d.HTTP2.PseudoHeaderOrder, h[:j+1])
				}
			}
			if f.Priority != nil {
				if f.Priority.Exclusive < 0 || f.Priority.Exclusive > 1 {
					return nil, fmt.Errorf("peet import: priority exclusive must be 0 or 1")
				}
				d.HTTP2.HeaderPriority = &Priority{Weight: f.Priority.Weight, StreamDep: f.Priority.DependsOn, Exclusive: f.Priority.Exclusive == 1}
			}
		case "PRIORITY":
			if headersSeen || f.Priority == nil || f.Priority.Exclusive < 0 || f.Priority.Exclusive > 1 {
				return nil, fmt.Errorf("peet import: initial PRIORITY frame is malformed or occurs after request HEADERS")
			}
			d.HTTP2.InitialPriorities = append(d.HTTP2.InitialPriorities, PriorityFrame{StreamID: f.StreamID, Priority: Priority{Weight: f.Priority.Weight, StreamDep: f.Priority.DependsOn, Exclusive: f.Priority.Exclusive == 1}})
		default:
			return nil, fmt.Errorf("peet import: sent_frames[%d]: unsupported frame type %q", i, f.Type)
		}
	}
	if !settingsSeen || !headersSeen {
		return nil, fmt.Errorf("peet import: capture requires SETTINGS and HEADERS frames")
	}
	return compile(d)
}

type peetExtension struct {
	Name          string              `json:"name"`
	Data          string              `json:"data"`
	ServerName    string              `json:"server_name"`
	SharedKeys    []map[string]string `json:"shared_keys"`
	Signatures    []string            `json:"signature_algorithms"`
	StatusRequest *struct {
		Type       string `json:"certificate_status_type"`
		Responders int    `json:"responder_id_list_length"`
		Extensions int    `json:"request_extensions_length"`
	} `json:"status_request"`
	Points                   []string `json:"elliptic_curves_point_formats"`
	Versions                 []string `json:"versions"`
	Protocols                []string `json:"protocols"`
	Groups                   []string `json:"supported_groups"`
	MasterSecretData         string   `json:"master_secret_data"`
	ExtendedMasterSecretData string   `json:"extended_master_secret_data"`
	Algorithms               []string `json:"algorithms"`
	PSKMode                  string   `json:"PSK_Key_Exchange_Mode"`
	SignatureHashes          []string `json:"signature_hash_algorithms"`
	PaddingLength            *uint32  `json:"padding_data_length"`
	RecordSizeLimit          *uint16  `json:"record_size_limit"`
}

func importExtension(raw []byte, allowOpaque bool, reference *signatureReference) (extension, error) {
	var pe peetExtension
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pe); err != nil {
		return extension{}, err
	}
	e := extension{}
	if strings.Contains(pe.Name, "GREASE") {
		if pe.Data != "" && pe.Data != "00" {
			return e, fmt.Errorf("unsupported GREASE extension body")
		}
		e.Type = "grease"
		return e, nil
	}
	id, err := parseNumericName(pe.Name)
	if err != nil {
		return e, err
	}
	switch id {
	case 0:
		e.Type = "server_name"
	case 5:
		e.Type = "status_request"
		if pe.StatusRequest == nil || pe.StatusRequest.Responders != 0 || pe.StatusRequest.Extensions != 0 || (pe.StatusRequest.Type != "OSCP (1)" && pe.StatusRequest.Type != "OCSP (1)") {
			return e, fmt.Errorf("only empty OCSP status_request is supported")
		}
	case 10:
		e.Type = "supported_groups"
		e.Values, err = parseNamedList(pe.Groups, dicttls.DictSupportedGroupsNameIndexed)
	case 11:
		e.Type = "ec_point_formats"
		e.Values, err = parseNamedList(pe.Points, nil)
	case 13, 34, 50:
		e.Type = map[uint16]string{13: "signature_algorithms", 34: "delegated_credentials", 50: "signature_algorithms_cert"}[id]
		signatures := pe.Signatures
		if id == 34 {
			signatures = pe.SignatureHashes
		}
		e.Values, err = parseNamedList(signatures, dicttls.DictSignatureSchemeNameIndexed)
		if len(signatures) == 0 && pe.Data != "" {
			b, decodeErr := hex.DecodeString(pe.Data)
			if decodeErr != nil || len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 || len(b)%2 != 0 {
				return e, fmt.Errorf("invalid signature algorithm vector payload")
			}
			for i := 2; i < len(b); i += 2 {
				e.Values = append(e.Values, binary.BigEndian.Uint16(b[i:i+2]))
			}
		}
		if err == nil && id == 13 {
			e.Values, err = reconcileSignatures(e.Values, pe.Signatures, reference)
		}
		if err == nil {
			for _, v := range e.Values {
				if !isGREASE(v) && !supportedSignature(v) {
					if !allowOpaque {
						return e, fmt.Errorf("signature scheme 0x%04x is unsupported; ImportPeet(data, true) opts in to advertisement only", v)
					}
					e.AllowUnsupported = true
				}
			}
		}
	case 16:
		e.Type = "alpn"
		e.Protocols = pe.Protocols
	case 17:
		e.Type = "status_request_v2"
	case 18:
		e.Type = "sct"
	case 21:
		e.Type = "padding"
		if pe.PaddingLength != nil {
			// TrackMe reports len(ext.Data), where Data is a hex string, so
			// padding_data_length counts hex characters rather than bytes.
			// Native padding_length and uTLS PaddingLen both count wire bytes.
			if *pe.PaddingLength%2 != 0 || *pe.PaddingLength > 2*65535 {
				return e, fmt.Errorf("padding_data_length must be an even hex-character count in 0..131070")
			}
			n := uint16(*pe.PaddingLength / 2)
			e.PaddingLength = &n
		} else {
			b, decodeErr := hex.DecodeString(pe.Data)
			if decodeErr != nil || len(b) > 65535 {
				return e, fmt.Errorf("invalid padding payload")
			}
			for _, v := range b {
				if v != 0 {
					return e, fmt.Errorf("padding payload must contain zero bytes")
				}
			}
			n := uint16(len(b))
			e.PaddingLength = &n
		}
	case 23:
		e.Type = "extended_master_secret"
		if pe.MasterSecretData != "" || pe.ExtendedMasterSecretData != "" {
			return e, fmt.Errorf("unexpected extended_master_secret payload")
		}
	case 27:
		e.Type = "compress_certificate"
		e.Values, err = parseNamedList(pe.Algorithms, nil)
	case 24:
		e.Type = "token_binding"
		b, decodeErr := hex.DecodeString(pe.Data)
		if decodeErr != nil || len(b) < 4 || int(b[2]) != len(b)-3 {
			return e, fmt.Errorf("invalid token_binding version/key parameter payload")
		}
		e.Values = []uint16{uint16(b[0]), uint16(b[1])}
		for _, v := range b[3:] {
			e.Values = append(e.Values, uint16(v))
		}
	case 28:
		e.Type = "record_size_limit"
		e.RecordSizeLimit = pe.RecordSizeLimit
		if e.RecordSizeLimit == nil {
			b, decodeErr := hex.DecodeString(pe.Data)
			if decodeErr != nil || len(b) != 2 {
				return e, fmt.Errorf("record_size_limit requires a two-byte payload")
			}
			n := binary.BigEndian.Uint16(b)
			e.RecordSizeLimit = &n
		}
	case 35:
		e.Type = "session_ticket"
		if pe.Data != "" {
			return e, fmt.Errorf("captured session ticket must not be replayed")
		}
	case 43:
		e.Type = "supported_versions"
		e.Values, err = parseNamedList(pe.Versions, map[string]uint16{"TLS 1.3": 772, "TLS 1.2": 771, "TLS 1.1": 770, "TLS 1.0": 769, "0300": 768, "SSL 3.0": 768})
	case 45:
		e.Type = "psk_key_exchange_modes"
		var v uint16
		v, err = parseNumericName(pe.PSKMode)
		e.Values = []uint16{v}
	case 51:
		e.Type = "key_share"
		for _, key := range pe.SharedKeys {
			if len(key) != 1 {
				return e, fmt.Errorf("each shared_keys entry must contain exactly one group")
			}
			for name := range key {
				v, er := parseNumericName(name)
				if er != nil {
					return e, er
				}
				e.Values = append(e.Values, v)
			}
		}
	case 17513:
		e.Type = "application_settings"
		e.Protocols = pe.Protocols
	case 13172:
		e.Type = "npn"
		e.Protocols = pe.Protocols
		if len(e.Protocols) == 0 {
			e.Protocols = []string{"h2", "http/1.1"}
		}
	case 30031, 30032:
		e.Type = map[uint16]string{30031: "channel_id_old", 30032: "channel_id"}[id]
	case 17613:
		e.Type = "application_settings_new"
		e.Protocols = pe.Protocols
	case 65037:
		e.Type = "grease_ech"
		e.PayloadLengths, err = importECHShape(pe.Data)
		if err == nil {
			b, _ := hex.DecodeString(pe.Data)
			kdf, aead := binary.BigEndian.Uint16(b[1:3]), binary.BigEndian.Uint16(b[3:5])
			if kdf != 1 || aead != 1 {
				e.ECHCipherSuites = []echCipherSuite{{KDFID: kdf, AEADID: aead}}
			}
		}
	case 65281:
		e.Type = "renegotiation_info"
		if pe.Data != "00" {
			return e, fmt.Errorf("only initial empty renegotiation_info is supported")
		}
	default:
		if !allowOpaque {
			return e, fmt.Errorf("unsupported extension %d; ImportPeet(data, true) explicitly permits audited opaque payloads", id)
		}
		var fields map[string]json.RawMessage
		json.Unmarshal(raw, &fields)
		if _, present := fields["data"]; !present {
			return e, fmt.Errorf("extension %d has no raw data payload to preserve", id)
		}
		e.Type = "raw"
		e.ID = &id
		e.DataHex = &pe.Data
		e.AllowOpaque = true
	}
	if err != nil {
		return e, err
	}
	if pe.Data != "" && !slices.Contains([]uint16{13, 21, 24, 28, 34, 35, 50, 65037, 65281}, id) && e.Type != "raw" {
		return e, fmt.Errorf("unexpected opaque data on typed extension %d", id)
	}
	return e, nil
}

type signatureReference struct {
	PeetPrint string
	JA4Raw    string
}

// Peet's historical name table labels Ed448 (0x0808) as ed25519. The numeric
// fingerprint vectors retain its actual ID. Cross-check both references and
// permit this known label ambiguity only; inconsistent captures are errors.
func reconcileSignatures(values []uint16, labels []string, reference *signatureReference) ([]uint16, error) {
	if reference == nil {
		return values, nil
	}
	var peet, ja4 []uint16
	parse := func(input, separator string, base int) ([]uint16, error) {
		if input == "" {
			return []uint16{}, nil
		}
		var out []uint16
		for _, part := range strings.Split(input, separator) {
			if part == "GREASE" {
				out = append(out, GREASE)
				continue
			}
			n, err := strconv.ParseUint(part, base, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid numeric signature fingerprint")
			}
			v := uint16(n)
			if isGREASE(v) {
				v = GREASE
			}
			out = append(out, v)
		}
		return out, nil
	}
	var err error
	if reference.PeetPrint != "" {
		parts := strings.Split(reference.PeetPrint, "|")
		if len(parts) < 4 {
			return nil, fmt.Errorf("invalid peetprint signature vector")
		}
		peet, err = parse(parts[3], "-", 10)
		if err != nil {
			return nil, err
		}
	}
	if reference.JA4Raw != "" {
		parts := strings.Split(reference.JA4Raw, "_")
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid ja4_r signature vector")
		}
		ja4, err = parse(parts[3], ",", 16)
		if err != nil {
			return nil, err
		}
	}
	withoutGrease := func(in []uint16) []uint16 {
		out := make([]uint16, 0, len(in))
		for _, v := range in {
			if !isGREASE(v) {
				out = append(out, v)
			}
		}
		return out
	}
	if peet != nil && ja4 != nil && !slices.Equal(withoutGrease(peet), withoutGrease(ja4)) {
		return nil, fmt.Errorf("peetprint and ja4_r signature vectors disagree")
	}
	expected := peet
	if expected == nil && ja4 != nil {
		if len(withoutGrease(values)) != len(ja4) {
			return nil, fmt.Errorf("signature labels and ja4_r have different lengths")
		}
		expected = slices.Clone(values)
		j := 0
		for i, v := range values {
			if !isGREASE(v) {
				expected[i] = ja4[j]
				j++
			}
		}
	}
	if expected == nil {
		return values, nil
	}
	if len(expected) != len(values) {
		return nil, fmt.Errorf("signature labels and peetprint have different lengths")
	}
	out := slices.Clone(values)
	for i, want := range expected {
		if want == values[i] || (isGREASE(want) && isGREASE(values[i])) {
			continue
		}
		if i < len(labels) && labels[i] == "ed25519" && values[i] == 0x0807 && want == 0x0808 {
			out[i] = want
			continue
		}
		return nil, fmt.Errorf("signature label/numeric fingerprint disagreement at position %d (label ID 0x%04x, fingerprint ID 0x%04x)", i, values[i], want)
	}
	return out, nil
}

func parseCipher(raw json.RawMessage) (uint16, error) {
	var numeric uint16
	if err := json.Unmarshal(raw, &numeric); err == nil {
		return numeric, nil
	}
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return 0, fmt.Errorf("cipher must be an IANA name or uint16 ID")
	}
	if id, ok := ianaCipherSuites[name]; ok {
		return id, nil
	}
	if name == "TLS_EMPTY_RENEGOTIATION_INFO" {
		return 0x00ff, nil
	}
	if name == "TLS_FALLBACK" {
		return 0x5600, nil
	}
	if id, ok := dicttls.DictCipherSuiteNameIndexed[name]; ok {
		return id, nil
	}
	return parseNumericName(name)
}
func parseNamedList(names []string, known map[string]uint16) ([]uint16, error) {
	out := make([]uint16, 0, len(names))
	for _, s := range names {
		v, ok := known[s]
		if !ok {
			var err error
			v, err = parseNumericName(s)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, v)
	}
	return out, nil
}
func parseNumericName(s string) (uint16, error) {
	if strings.Contains(s, "GREASE") {
		return GREASE, nil
	}
	original := s
	if i := strings.LastIndex(s, "("); i >= 0 && strings.HasSuffix(s, ")") {
		s = s[i+1 : len(s)-1]
	} else if strings.HasPrefix(s, "Unknown extension ") {
		s = strings.TrimPrefix(s, "Unknown extension ")
	} else if strings.HasPrefix(s, "Unknown curve ") {
		s = strings.TrimPrefix(s, "Unknown curve ")
	}
	base := 10
	if strings.HasPrefix(s, "0x") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 16)
	if err != nil {
		return 0, fmt.Errorf("unknown numeric TLS name %q", original)
	}
	return uint16(v), nil
}
func importECHShape(s string) ([]uint16, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid ECH hex: %w", err)
	}
	// Decode only shape; never retain config ID, encapsulated key or ciphertext.
	if len(b) < 10 || b[0] != 0 {
		return nil, fmt.Errorf("only outer GREASE ECH shape is importable; real ECH secret state is never replayed")
	}
	keyLen := int(binary.BigEndian.Uint16(b[6:8]))
	if keyLen != 32 || len(b) < 10+keyLen {
		return nil, fmt.Errorf("invalid or unsupported ECH encapsulated key length")
	}
	n := int(binary.BigEndian.Uint16(b[8+keyLen : 10+keyLen]))
	if n <= 16 || n != len(b)-10-keyLen {
		return nil, fmt.Errorf("invalid ECH payload length")
	}
	return []uint16{uint16(n - 16)}, nil
}
func parseSetting(s string) (Setting, error) {
	parts := strings.Split(s, "=")
	if len(parts) != 2 {
		return Setting{}, fmt.Errorf("peet import: malformed setting %q", s)
	}
	ids := map[string]uint16{"HEADER_TABLE_SIZE": 1, "ENABLE_PUSH": 2, "MAX_CONCURRENT_STREAMS": 3, "INITIAL_WINDOW_SIZE": 4, "MAX_FRAME_SIZE": 5, "MAX_HEADER_LIST_SIZE": 6, "ENABLE_CONNECT_PROTOCOL": 8, "NO_RFC7540_PRIORITIES": 9}
	id, ok := ids[strings.TrimSpace(parts[0])]
	if !ok {
		var err error
		id, err = parseNumericName(strings.TrimPrefix(strings.TrimSpace(parts[0]), "UNKNOWN_SETTING_"))
		if err != nil {
			return Setting{}, fmt.Errorf("peet import: unknown setting %q", parts[0])
		}
	}
	value, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
	if err != nil {
		return Setting{}, fmt.Errorf("peet import: invalid setting %q", s)
	}
	return Setting{ID: id, Value: uint32(value)}, nil
}
