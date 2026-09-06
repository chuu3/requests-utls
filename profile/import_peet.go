package profile

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// ImportPeet converts a tls.peet.ws /api/all capture to a native profile.
// Capture metadata, request header values, randoms, session IDs, SNI, tickets,
// key-share bytes and ECH ciphertext are never stored. allowOpaque explicitly
// permits raw extension 51764 and advertisement of unsupported signature IDs;
// both are reported by Limitations and encoded as explicit native opt-ins.
func ImportPeet(data []byte, allowOpaque bool) (*Profile, error) {
	var c struct {
		HTTPVersion string `json:"http_version"`
		TLS         struct {
			Ciphers    []string          `json:"ciphers"`
			Extensions []json.RawMessage `json:"extensions"`
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
	if c.HTTPVersion != "h2" {
		return nil, fmt.Errorf("peet import: expected http_version h2, got %q", c.HTTPVersion)
	}
	d := document{SchemaVersion: 1, Name: "imported-peet-profile", TLS: tlsConfig{MinVersion: 771, MaxVersion: 772}, Notes: []string{
		"Imported from a single tls.peet.ws capture. Extension order is fixed to that sample, not a browser's complete randomized ordering policy.",
		"IP addresses, capture metadata, request header values, SNI, randoms, session IDs, key material and ECH ciphertext were removed; dynamic TLS values are generated per connection.",
		"GREASE extension bodies follow uTLS's BoringSSL behavior: first empty, second one zero byte; the capture does not expose their lengths.",
	}}
	cipherNames := map[string]uint16{}
	for _, s := range append(utls.CipherSuites(), utls.InsecureCipherSuites()...) {
		cipherNames[s.Name] = s.ID
	}
	for i, s := range c.TLS.Ciphers {
		var id uint16
		if strings.Contains(s, "GREASE") {
			id = GREASE
		} else {
			var ok bool
			id, ok = cipherNames[s]
			if !ok {
				return nil, fmt.Errorf("peet import: ciphers[%d]: unknown cipher %q", i, s)
			}
		}
		d.TLS.CipherSuites = append(d.TLS.CipherSuites, id)
	}
	for i, raw := range c.TLS.Extensions {
		e, err := importExtension(raw, allowOpaque)
		if err != nil {
			return nil, fmt.Errorf("peet import: tls.extensions[%d]: %w", i, err)
		}
		d.TLS.Extensions = append(d.TLS.Extensions, e)
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
}

func importExtension(raw []byte, allowOpaque bool) (extension, error) {
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
		e.Values, err = parseNamedList(pe.Groups, nil)
	case 11:
		e.Type = "ec_point_formats"
		e.Values, err = parseNamedList(pe.Points, nil)
	case 13:
		e.Type = "signature_algorithms"
		e.Values, err = parseNamedList(pe.Signatures, map[string]uint16{
			"rsa_pkcs1_sha256": 0x0401, "rsa_pkcs1_sha384": 0x0501, "rsa_pkcs1_sha512": 0x0601,
			"rsa_pss_rsae_sha256": 0x0804, "rsa_pss_rsae_sha384": 0x0805, "rsa_pss_rsae_sha512": 0x0806,
			"ecdsa_secp256r1_sha256": 0x0403, "ecdsa_secp384r1_sha384": 0x0503, "ecdsa_secp521r1_sha512": 0x0603,
			"ed25519": 0x0807, "rsa_pkcs1_sha1": 0x0201, "ecdsa_sha1": 0x0203,
		})
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
	case 18:
		e.Type = "sct"
	case 23:
		e.Type = "extended_master_secret"
		if pe.MasterSecretData != "" || pe.ExtendedMasterSecretData != "" {
			return e, fmt.Errorf("unexpected extended_master_secret payload")
		}
	case 27:
		e.Type = "compress_certificate"
		e.Values, err = parseNamedList(pe.Algorithms, nil)
	case 35:
		e.Type = "session_ticket"
		if pe.Data != "" {
			return e, fmt.Errorf("captured session ticket must not be replayed")
		}
	case 43:
		e.Type = "supported_versions"
		e.Values, err = parseNamedList(pe.Versions, map[string]uint16{"TLS 1.3": 772, "TLS 1.2": 771})
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
	case 17613:
		e.Type = "application_settings_new"
		e.Protocols = pe.Protocols
	case 65037:
		e.Type = "grease_ech"
		e.PayloadLengths, err = importECHShape(pe.Data)
	case 65281:
		e.Type = "renegotiation_info"
		if pe.Data != "00" {
			return e, fmt.Errorf("only initial empty renegotiation_info is supported")
		}
	default:
		if !allowOpaque {
			return e, fmt.Errorf("unsupported extension %d; ImportPeet(data, true) explicitly permits audited opaque payloads", id)
		}
		e.Type = "raw"
		e.ID = &id
		e.DataHex = &pe.Data
		e.AllowOpaque = true
	}
	if err != nil {
		return e, err
	}
	if pe.Data != "" && id != 35 && id != 65037 && id != 65281 && e.Type != "raw" {
		return e, fmt.Errorf("unexpected opaque data on typed extension %d", id)
	}
	return e, nil
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
	if len(b) < 10 || b[0] != 0 || binary.BigEndian.Uint16(b[1:3]) != 1 || binary.BigEndian.Uint16(b[3:5]) != 1 {
		return nil, fmt.Errorf("only outer GREASE ECH with HKDF-SHA256/AES-128-GCM is supported; a capture does not establish real ECH support")
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
		return Setting{}, fmt.Errorf("peet import: unknown setting %q", parts[0])
	}
	value, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
	if err != nil {
		return Setting{}, fmt.Errorf("peet import: invalid setting %q", s)
	}
	return Setting{ID: id, Value: uint32(value)}, nil
}
