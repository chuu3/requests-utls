package profile

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestIANAAndFutureCipherIDs(t *testing.T) {
	if len(ianaCipherSuites) < 350 {
		t.Fatal("incomplete IANA snapshot")
	}
	for _, name := range []string{`"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"`, `"0xc008"`, `49160`} {
		id, err := parseCipher([]byte(name))
		if err != nil || id != 0xc008 {
			t.Fatalf("%s: %d %v", name, id, err)
		}
	}
	p, err := Load([]byte(strings.Replace(basicProfile, "[4865,4866,4867,49199,49200]", "[4865,49160,65534]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := p.NewClientHelloSpec()
	if !slices.Equal(spec.CipherSuites, []uint16{4865, 49160, 65534}) || len(p.Limitations()) != 2 {
		t.Fatal("wire cipher list or unsupported limitations were lost")
	}
}

func TestAdditionalTypedExtensionsPreserveValues(t *testing.T) {
	input := strings.Replace(basicProfile, `[1027,2052,1025]`, `[1027,2052,2052,1025]`, 1)
	input = strings.Replace(input, `{"type":"server_name"}`, `{"type":"server_name"},{"type":"padding","padding_length":12},{"type":"record_size_limit","record_size_limit":16385},{"type":"delegated_credentials","values":[1027,2052]},{"type":"signature_algorithms_cert","values":[2052,2052]}`, 1)
	input = strings.Replace(input, `"supported_groups","values":[29,23]`, `"supported_groups","values":[29,23,256,257]`, 1)
	p, err := Load([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := p.NewClientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Extensions[1].(*utls.UtlsPaddingExtension).PaddingLen != 12 {
		t.Fatal("padding lost")
	}
	if spec.Extensions[2].(*utls.FakeRecordSizeLimitExtension).Limit != 16385 {
		t.Fatal("record limit lost")
	}
	if !slices.Equal(spec.Extensions[4].(*utls.SignatureAlgorithmsCertExtension).SupportedSignatureAlgorithms, []utls.SignatureScheme{2052, 2052}) {
		t.Fatal("duplicate signature dropped")
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	u := utls.UClient(client, &utls.Config{ServerName: "local.test"}, utls.HelloCustom)
	if err := u.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(u.HandshakeState.Hello.SupportedSignatureAlgorithms, []utls.SignatureScheme{1027, 2052, 2052, 1025}) {
		t.Fatal("uTLS discarded duplicate signatures")
	}
}

func TestUnknownStaticExtensionsAndSecretRejection(t *testing.T) {
	p, err := Load([]byte(strings.Replace(basicProfile, `{"type":"server_name"}`, `{"type":"server_name"},{"type":"raw","id":60000,"data_hex":"123456","allow_opaque":true}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := p.NewClientHelloSpec()
	raw := spec.Extensions[1].(*utls.GenericExtension)
	if raw.Id != 60000 || !bytes.Equal(raw.Data, []byte{0x12, 0x34, 0x56}) {
		t.Fatal("raw payload changed")
	}
	for _, id := range []uint16{0, 35, 41, 42, 44, 51, 65037, 65486} {
		input := strings.Replace(basicProfile, `{"type":"server_name"}`, fmt.Sprintf(`{"type":"raw","id":%d,"data_hex":"00","allow_opaque":true}`, id), 1)
		if _, err := Load([]byte(input)); err == nil {
			t.Errorf("dynamic raw extension %d accepted", id)
		}
		var capture map[string]any
		json.Unmarshal(syntheticPeetCapture(), &capture)
		if slices.Contains([]uint16{35, 41, 42, 44}, id) {
			capture["tls"].(map[string]any)["extensions"] = []any{map[string]any{"name": fmt.Sprintf("extension (%d)", id), "data": "00"}}
			encoded, _ := json.Marshal(capture)
			if _, err := ImportPeet(encoded, true); err == nil || !strings.Contains(err.Error(), "resumed/retry") {
				t.Errorf("resumption capture %d was not explicitly rejected: %v", id, err)
			}
		}
	}
}

func TestPeetPaddingLengthCountsHexCharacters(t *testing.T) {
	for _, tc := range []struct {
		capture string
		bytes   int
	}{
		{`{"name":"padding (21)","padding_data_length":402}`, 201},
		{`{"name":"padding (21)","padding_data_length":0}`, 0},
		{`{"name":"padding (21)","padding_data_length":131070}`, 65535},
		{`{"name":"padding (21)","data":"000000"}`, 3},
	} {
		e, err := importExtension([]byte(tc.capture), false, nil)
		if err != nil {
			t.Fatal(err)
		}
		if e.PaddingLength == nil || int(*e.PaddingLength) != tc.bytes {
			t.Fatalf("Peet padding conversion: got %v, want %d bytes", e.PaddingLength, tc.bytes)
		}
		wire := &utls.UtlsPaddingExtension{PaddingLen: int(*e.PaddingLength), WillPad: true}
		buf := make([]byte, wire.Len())
		n, err := wire.Read(buf)
		if err != io.EOF || n != tc.bytes+4 || int(binary.BigEndian.Uint16(buf[2:4])) != tc.bytes || !bytes.Equal(buf[4:], make([]byte, tc.bytes)) {
			t.Fatalf("padding wire payload has wrong size or data: length=%d, err=%v", n, err)
		}
	}
	for _, capture := range []string{
		`{"name":"padding (21)","padding_data_length":3}`,
		`{"name":"padding (21)","padding_data_length":131072}`,
		`{"name":"padding (21)","padding_data_length":-2}`,
		`{"name":"padding (21)","data":"01"}`,
	} {
		if _, err := importExtension([]byte(capture), false, nil); err == nil {
			t.Fatalf("invalid padding capture was accepted: %s", capture)
		}
	}
}

func TestRandomJA3LeavesProfileAndPinnedPositionsUnchanged(t *testing.T) {
	input := strings.Replace(basicProfile, `{"type":"server_name"}`, `{"type":"grease"},{"type":"server_name"},{"type":"padding","padding_length":0}`, 1)
	p, err := Load([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := json.Marshal(p)
	before, _ := p.NewClientHelloSpec()
	orders := sync.Map{}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spec, err := p.NewClientHelloSpecWithOptions(ClientHelloOptions{RandomJA3: true})
			if err != nil {
				t.Error(err)
				return
			}
			if _, ok := spec.Extensions[0].(*utls.UtlsGREASEExtension); !ok {
				t.Error("GREASE moved")
			}
			if _, ok := spec.Extensions[2].(*utls.UtlsPaddingExtension); !ok {
				t.Error("padding moved")
			}
			key := ""
			for _, e := range spec.Extensions {
				key += fmt.Sprintf("%T;", e)
			}
			orders.Store(key, true)
			spec.CipherSuites[0] = 0
		}()
	}
	wg.Wait()
	count := 0
	orders.Range(func(_, _ any) bool { count++; return true })
	if count < 2 {
		t.Fatal("extension order never randomized")
	}
	after, _ := json.Marshal(p)
	if !bytes.Equal(initial, after) {
		t.Fatal("profile was mutated")
	}
	fixed, _ := p.NewClientHelloSpec()
	if !reflect.DeepEqual(before, fixed) {
		t.Fatal("fixed order changed")
	}
}

func TestHTTP1CaptureAndForcedSpec(t *testing.T) {
	var capture map[string]any
	json.Unmarshal(syntheticPeetCapture(), &capture)
	capture["http_version"] = "HTTP/1.1"
	delete(capture, "http2")
	encoded, _ := json.Marshal(capture)
	p, err := ImportPeet(encoded, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.HTTPVersion() != "http/1.1" {
		t.Fatal("H1 preference lost")
	}
	fixed, err := Load([]byte(strings.Replace(basicProfile, `{"type":"server_name"}`, `{"type":"server_name"},{"type":"application_settings_new","protocols":["h2"]}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := fixed.NewClientHelloSpecWithOptions(ClientHelloOptions{ForceHTTP1: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range spec.Extensions {
		switch e := e.(type) {
		case *utls.ALPNExtension:
			if !slices.Equal(e.AlpnProtocols, []string{"http/1.1"}) {
				t.Fatal("H2 ALPN remains")
			}
		case *utls.ApplicationSettingsExtensionNew:
			t.Fatal("H2 ALPS remains")
		}
	}
	setting, err := parseSetting("UNKNOWN_SETTING_43578 = 42")
	if err != nil || setting.ID != 43578 || setting.Value != 42 {
		t.Fatal("unknown numeric H2 setting lost", err)
	}
}

func TestPeetEd448LabelAmbiguityUsesCrossCheckedNumericIDs(t *testing.T) {
	for _, reference := range []*signatureReference{
		{PeetPrint: "x|x|x|2055-2056", JA4Raw: "t13d0000h1_x_x_0807,0808"},
		{PeetPrint: "x|x|x|2055-2056"},
		{JA4Raw: "t13d0000h1_x_x_0807,0808"},
	} {
		values, err := reconcileSignatures([]uint16{0x0807, 0x0807}, []string{"ed25519", "ed25519"}, reference)
		if err != nil || !slices.Equal(values, []uint16{0x0807, 0x0808}) {
			t.Fatalf("Ed448 identity lost: %v %v", values, err)
		}
	}
	_, err := reconcileSignatures([]uint16{0x0807, 0x0807}, []string{"ed25519", "ed25519"}, &signatureReference{PeetPrint: "x|x|x|2055-2056", JA4Raw: "t13d0000h1_x_x_0807,0807"})
	if err == nil {
		t.Fatal("conflicting numeric fingerprints accepted")
	}
	_, err = reconcileSignatures([]uint16{0x0804}, []string{"rsa_pss_rsae_sha256"}, &signatureReference{PeetPrint: "x|x|x|2055"})
	if err == nil {
		t.Fatal("arbitrary label/ID conflict silently rewritten")
	}
	values, err := reconcileSignatures([]uint16{GREASE, 0x0807}, []string{"GREASE", "ed25519"}, &signatureReference{PeetPrint: "x|x|x|GREASE-2055", JA4Raw: "t13d0000h1_x_x_0807"})
	if err != nil || !slices.Equal(values, []uint16{GREASE, 0x0807}) {
		t.Fatal("JA4 GREASE filtering was mishandled", err)
	}

	var capture map[string]any
	json.Unmarshal(syntheticPeetCapture(), &capture)
	tls := capture["tls"].(map[string]any)
	extensions := tls["extensions"].([]any)
	extensions[2] = map[string]any{"name": "signature_algorithms (13)", "signature_algorithms": []string{"ed25519", "ed25519"}}
	tls["peetprint"] = "x|x|x|2055-2056"
	tls["ja4_r"] = "t13d0000h1_x_x_0807,0808"
	encoded, _ := json.Marshal(capture)
	p, err := ImportPeet(encoded, true)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := p.NewClientHelloSpec()
	if !slices.Equal(spec.Extensions[2].(*utls.SignatureAlgorithmsExtension).SupportedSignatureAlgorithms, []utls.SignatureScheme{0x0807, 0x0808}) {
		t.Fatal("importer did not preserve Ed448 wire ID")
	}
}

// This optional acceptance scan reads only explicitly supplied local captures.
// It never sends network traffic or copies captured secrets into test fixtures.
func TestLocalCaptureCorpus(t *testing.T) {
	dirs := os.Getenv("REQUESTS_UTLS_CAPTURE_DIRS")
	if dirs == "" {
		t.Skip("set REQUESTS_UTLS_CAPTURE_DIRS for a local capture corpus scan")
	}
	passed, rejected, invalid := 0, 0, 0
	for _, dir := range filepath.SplitList(dirs) {
		paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			p, err := ImportPeet(raw, true)
			if err != nil {
				var snapshot struct {
					TLS struct {
						Ciphers    []json.RawMessage `json:"ciphers"`
						Extensions []json.RawMessage `json:"extensions"`
					} `json:"tls"`
				}
				if json.Unmarshal(raw, &snapshot) == nil && len(snapshot.TLS.Ciphers) == 0 && len(snapshot.TLS.Extensions) == 0 {
					invalid++
					continue
				}
				if strings.Contains(err.Error(), "resumed/retry") {
					rejected++
					continue
				}
				t.Errorf("%s: %v", filepath.Base(path), err)
				continue
			}
			spec, err := p.NewClientHelloSpec()
			if err != nil {
				t.Errorf("%s spec: %v", filepath.Base(path), err)
				continue
			}
			client, server := net.Pipe()
			u := utls.UClient(client, &utls.Config{ServerName: "tls.peet.ws"}, utls.HelloCustom)
			if err = u.ApplyPreset(spec); err == nil {
				err = u.BuildHandshakeState()
			}
			client.Close()
			server.Close()
			if err != nil {
				t.Errorf("%s ClientHello: %v", filepath.Base(path), err)
				continue
			}
			passed++
		}
	}
	t.Logf("local ClientHello build passed=%d; explicitly rejected resumed/retry captures=%d; missing TLS data=%d", passed, rejected, invalid)
}
