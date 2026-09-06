package profile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	utls "github.com/refraction-networking/utls"
)

const basicProfile = `{"schema_version":1,"name":"local-test","tls":{"min_version":771,"max_version":772,"cipher_suites":[4865,4866,4867,49199,49200],"extensions":[{"type":"server_name"},{"type":"supported_groups","values":[29,23]},{"type":"signature_algorithms","values":[1027,2052,1025]},{"type":"alpn","protocols":["h2","http/1.1"]},{"type":"supported_versions","values":[772,771]},{"type":"key_share","values":[29]},{"type":"psk_key_exchange_modes","values":[1]}]},"http2":{"settings":[{"id":1,"value":65536},{"id":2,"value":0},{"id":4,"value":6291456}],"connection_window_update":15663105,"pseudo_header_order":[":method",":authority",":scheme",":path"],"header_priority":{"stream_dep":0,"exclusive":true,"weight":256}}}`

func TestRejectInvalidProfiles(t *testing.T) {
	cases := map[string]string{
		"unknown root":          strings.Replace(basicProfile, `"name":`, `"mystery":true,"name":`, 1),
		"unknown nested":        strings.Replace(basicProfile, `"min_version":`, `"tls_profile":{},"min_version":`, 1),
		"unknown version":       strings.Replace(basicProfile, `"schema_version":1`, `"schema_version":2`, 1),
		"unknown extension":     strings.Replace(basicProfile, `"server_name"`, `"future_handshake"`, 1),
		"wrong typed fields":    strings.Replace(basicProfile, `"type":"server_name"`, `"type":"server_name","values":[1]`, 1),
		"unsupported key share": strings.Replace(basicProfile, `"key_share","values":[29]`, `"key_share","values":[999]`, 1),
		"unsupported signature": strings.Replace(basicProfile, `[1027,2052,1025]`, `[2308,2052,1025]`, 1),
		"duplicate extension":   strings.Replace(basicProfile, `{"type":"server_name"}`, `{"type":"server_name"},{"type":"server_name"}`, 1),
		"raw without optin":     strings.Replace(basicProfile, `{"type":"server_name"}`, `{"type":"raw","id":51764,"data_hex":"00"}`, 1),
		"raw semantic bypass":   strings.Replace(basicProfile, `{"type":"server_name"}`, `{"type":"raw","id":41,"data_hex":"00","allow_opaque":true}`, 1),
		"malformed raw hex":     strings.Replace(basicProfile, `{"type":"server_name"}`, `{"type":"raw","id":51764,"data_hex":"bad","allow_opaque":true}`, 1),
		"invalid priority":      strings.Replace(basicProfile, `"weight":256`, `"weight":257`, 1),
		"window overflow":       strings.Replace(basicProfile, `"connection_window_update":15663105`, `"connection_window_update":2147483647`, 1),
		"invalid frame size":    strings.Replace(basicProfile, `{"id":1,"value":65536}`, `{"id":5,"value":100}`, 1),
		"duplicate pseudo":      strings.Replace(basicProfile, `":scheme"`, `":method"`, 1),
		"missing group":         strings.Replace(basicProfile, `"key_share","values":[29]`, `"key_share","values":[24]`, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(data)); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
}
func TestProfileDoesNotAliasMutableSpecsOrHTTP2(t *testing.T) {
	p, err := Load([]byte(basicProfile))
	if err != nil {
		t.Fatal(err)
	}
	hash := p.Hash()
	a, err := p.NewClientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}
	a.CipherSuites[0] = 0
	a.Extensions[1].(*utls.SupportedCurvesExtension).Curves[0] = 999
	a.Extensions[3].(*utls.ALPNExtension).AlpnProtocols[0] = "bad"
	a.Extensions[5].(*utls.KeyShareExtension).KeyShares[0].Data = []byte{42}
	h := p.HTTP2()
	h.Settings[0].Value = 0
	h.PseudoHeaderOrder[0] = "bad"
	h.HeaderPriority.Weight = 1
	b, err := p.NewClientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}
	if b.CipherSuites[0] != 4865 || b.Extensions[1].(*utls.SupportedCurvesExtension).Curves[0] != 29 || b.Extensions[3].(*utls.ALPNExtension).AlpnProtocols[0] != "h2" || b.Extensions[5].(*utls.KeyShareExtension).KeyShares[0].Data != nil {
		t.Fatal("spec mutation contaminated profile")
	}
	if p.HTTP2().Settings[0].Value != 65536 || p.HTTP2().PseudoHeaderOrder[0] != ":method" || p.HTTP2().HeaderPriority.Weight != 256 || p.Hash() != hash {
		t.Fatal("HTTP2 mutation contaminated profile")
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := Load(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if copy.Hash() != p.Hash() {
		t.Fatal("canonical hash changed on round trip")
	}
}
func TestConcurrentSpecBuildHasIndependentTLSState(t *testing.T) {
	p, err := Load([]byte(basicProfile))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spec, err := p.NewClientHelloSpec()
			if err != nil {
				t.Error(err)
				return
			}
			c, s := net.Pipe()
			defer c.Close()
			defer s.Close()
			u := utls.UClient(c, &utls.Config{ServerName: "local.test"}, utls.HelloCustom)
			if err := u.ApplyPreset(spec); err != nil {
				t.Error(err)
				return
			}
			if err := u.BuildHandshakeState(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
func TestChromeFixtureRegeneratesDynamicMaterial(t *testing.T) {
	raw, err := os.ReadFile("../profiles/chrome_152.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Limitations()) != 5 {
		t.Fatalf("expected raw, three signature and ALPS limitations: %v", p.Limitations())
	}
	forbidden := []string{"client_random", "session_id", "server_name\": \"tls.peet.ws", "210.13.90.194", "d9494236b8990c74191d30303ed69a3f4", "d07fa3ef75e4825419d119cb4c9eae51"}
	for _, s := range forbidden {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatalf("fixture leaked captured data %q", s)
		}
	}
	specs := make([]*utls.ClientHelloSpec, 2)
	randoms := make([][]byte, 2)
	for i := range specs {
		specs[i], err = p.NewClientHelloSpec()
		if err != nil {
			t.Fatal(err)
		}
		for _, ext := range specs[i].Extensions {
			if k, ok := ext.(*utls.KeyShareExtension); ok {
				for _, share := range k.KeyShares {
					if !isGREASE(uint16(share.Group)) && len(share.Data) != 0 {
						t.Fatal("captured key share was replayed")
					}
				}
			}
		}
		c, s := net.Pipe()
		u := utls.UClient(c, &utls.Config{ServerName: "fixture.test"}, utls.HelloCustom)
		if err := u.ApplyPreset(specs[i]); err != nil {
			t.Fatal(err)
		}
		if err := u.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		randoms[i] = bytes.Clone(u.HandshakeState.Hello.Random)
		c.Close()
		s.Close()
	}
	if bytes.Equal(randoms[0], randoms[1]) {
		t.Fatal("ClientHello random reused")
	}
	var keys [2][]byte
	var ech [2][]byte
	for i, spec := range specs {
		for _, ext := range spec.Extensions {
			switch e := ext.(type) {
			case *utls.KeyShareExtension:
				for _, k := range e.KeyShares {
					if k.Group == utls.X25519MLKEM768 {
						keys[i] = k.Data
						if len(k.Data) != 1216 {
							t.Fatalf("MLKEM key share length %d", len(k.Data))
						}
					}
				}
			case *utls.GREASEEncryptedClientHelloExtension:
				ech[i] = make([]byte, e.Len())
				e.Read(ech[i])
			}
		}
	}
	if len(keys[0]) == 0 || bytes.Equal(keys[0], keys[1]) {
		t.Fatal("hybrid key material reused")
	}
	if len(ech[0]) == 0 || bytes.Equal(ech[0], ech[1]) {
		t.Fatal("ECH random data reused")
	}
}

// A synthetic capture includes marker data that must never reach a native
// profile. It exercises the import contract without copying private captures.
func syntheticPeetCapture() []byte {
	ech := make([]byte, 42+144)
	ech[0] = 0
	ech[2] = 1
	ech[4] = 1
	ech[5] = 99
	ech[7] = 32
	ech[40] = 0
	ech[41] = 144
	for i := 8; i < 40; i++ {
		ech[i] = 0xab
	}
	for i := 42; i < len(ech); i++ {
		ech[i] = 0xcd
	}
	c := map[string]any{
		"http_version": "h2", "ip": "private-ip-marker", "tls": map[string]any{
			"ciphers": []string{"TLS_AES_128_GCM_SHA256"}, "client_random": "private-random-marker", "session_id": "private-session-marker",
			"extensions": []any{
				map[string]any{"name": "server_name (0)", "server_name": "private-name-marker"},
				map[string]any{"name": "supported_groups (10)", "supported_groups": []string{"X25519 (29)"}},
				map[string]any{"name": "signature_algorithms (13)", "signature_algorithms": []string{"rsa_pss_rsae_sha256"}},
				map[string]any{"name": "supported_versions (43)", "versions": []string{"TLS 1.3", "TLS 1.2"}},
				map[string]any{"name": "key_share (51)", "shared_keys": []any{map[string]string{"X25519 (29)": "private-key-marker"}}},
				map[string]any{"name": "extensionEncryptedClientHello (boringssl) (65037)", "data": hex.EncodeToString(ech)},
				map[string]any{"name": "Unknown extension 51764", "data": "0000"},
			},
		}, "http2": map[string]any{"sent_frames": []any{
			map[string]any{"frame_type": "SETTINGS", "settings": []string{"HEADER_TABLE_SIZE = 65536", "ENABLE_PUSH = 0"}},
			map[string]any{"frame_type": "WINDOW_UPDATE", "increment": 15663105},
			map[string]any{"frame_type": "HEADERS", "headers": []string{":method: GET", ":authority: private-name-marker", ":scheme: https", ":path: /", "cookie: private-cookie-marker"}},
		}},
	}
	b, _ := json.Marshal(c)
	return b
}
func TestPeetImportRequiresOptInAndSanitizes(t *testing.T) {
	raw := syntheticPeetCapture()
	if _, err := Load(raw); err == nil || !strings.Contains(err.Error(), "ImportPeet") {
		t.Fatal("Load must explain explicit importer")
	}
	if _, err := ImportPeet(raw, false); err == nil || !strings.Contains(err.Error(), "51764") {
		t.Fatalf("expected raw opt-in error: %v", err)
	}
	p, err := ImportPeet(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"private-", "abababab", "cdcdcdcd"} {
		if bytes.Contains(data, []byte(s)) {
			t.Fatalf("capture marker %q replayed", s)
		}
	}
	if !reflect.DeepEqual(p.HTTP2().PseudoHeaderOrder, []string{":method", ":authority", ":scheme", ":path"}) {
		t.Fatal("pseudo header order lost")
	}
	if !reflect.DeepEqual(p.doc.TLS.Extensions[5].PayloadLengths, []uint16{128}) {
		t.Fatal("ECH shape lost")
	}
	if p.doc.TLS.Extensions[6].Type != "raw" || !p.doc.TLS.Extensions[6].AllowOpaque {
		t.Fatal("explicit raw opt-in lost")
	}
	copy, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if copy.Hash() != p.Hash() {
		t.Fatal("import/export hash changed")
	}
}
