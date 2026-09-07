package requestsutls

import (
	"bytes"
	"crypto/md5" // JA3 defines MD5 as a fingerprint, not a security primitive.
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/chuu3/requests-utls/profile"
)

func chrome150GREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && value>>8 == value&255
}

func chrome150Normalize(values []uint16) []uint16 {
	out := append([]uint16(nil), values...)
	for i, value := range out {
		if chrome150GREASE(value) {
			out[i] = 2570
		}
	}
	return out
}

func chrome150JA3Vector(values []uint16) string {
	var out []string
	for _, value := range values {
		if !chrome150GREASE(value) {
			out = append(out, strconv.Itoa(int(value)))
		}
	}
	return strings.Join(out, "-")
}

func TestChrome150CaptureMatchesLocalClientHelloAndFreshKeys(t *testing.T) {
	var baseline struct {
		JA3                     string            `json:"ja3"`
		JA3Hash                 string            `json:"ja3_hash"`
		AkamaiFingerprint       string            `json:"akamai_fingerprint"`
		CipherSuites            []uint16          `json:"cipher_suites"`
		ExtensionOrder          []uint16          `json:"extension_order"`
		StableExtensionPayloads map[string]string `json:"stable_extension_payloads"`
		KeyShareLengths         []struct {
			Group  uint16 `json:"group"`
			Length int    `json:"length"`
		} `json:"key_share_lengths"`
		ECHShape struct {
			KDF                   uint16 `json:"kdf"`
			AEAD                  uint16 `json:"aead"`
			EncapsulatedKeyLength int    `json:"encapsulated_key_length"`
			PayloadLength         int    `json:"payload_length"`
		} `json:"ech_shape"`
	}
	data, err := os.ReadFile("testdata/chrome_150_fingerprint.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("profiles/chrome_150.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Limitations()) != 4 {
		t.Fatalf("expected three advertisement-only signatures and ALPS limitation, got %v", p.Limitations())
	}
	peer := testServer(t, nil)
	for range 2 {
		session := testSession(t, peer, func(options *Options) { options.Profile = p })
		if _, err := session.Do(testContext(t), Request{URL: peer.URL}); err != nil {
			t.Fatal(err)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := peer.Snapshot()
	if snapshot.Connections != 2 || len(snapshot.ClientHellos) != 2 || len(snapshot.Settings) != 2 || len(snapshot.Requests) != 2 {
		t.Fatalf("expected two independent full handshakes and requests: connections=%d hellos=%d settings=%d requests=%d", snapshot.Connections, len(snapshot.ClientHellos), len(snapshot.Settings), len(snapshot.Requests))
	}
	previousKeys := map[uint16][]byte{}
	var previousECH []byte
	for index, wire := range snapshot.ClientHellos {
		hello := parseHello(t, wire)
		if !reflect.DeepEqual(chrome150Normalize(hello.ciphers), baseline.CipherSuites) || !reflect.DeepEqual(chrome150Normalize(hello.extensions), baseline.ExtensionOrder) {
			t.Fatal("cipher or extension order differs from the original capture")
		}
		for name, wantHex := range baseline.StableExtensionPayloads {
			id, err := strconv.ParseUint(name, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			payload, present := hello.payloads[uint16(id)]
			if !present {
				t.Fatalf("missing captured static extension %d", id)
			}
			payload = bytes.Clone(payload)
			if id == 10 || id == 43 {
				offset := 2
				if id == 43 {
					offset = 1
				}
				for ; offset+1 < len(payload); offset += 2 {
					if chrome150GREASE(binary.BigEndian.Uint16(payload[offset:])) {
						binary.BigEndian.PutUint16(payload[offset:], 2570)
					}
				}
			}
			if hex.EncodeToString(payload) != wantHex {
				t.Fatalf("extension %d static payload differs from capture", id)
			}
		}
		shares := hello.payloads[51]
		if len(shares) < 2 || int(binary.BigEndian.Uint16(shares)) != len(shares)-2 {
			t.Fatal("invalid key_share vector")
		}
		shares = shares[2:]
		for _, expected := range baseline.KeyShareLengths {
			if len(shares) < 4 {
				t.Fatal("missing key_share entry")
			}
			group, length := binary.BigEndian.Uint16(shares), int(binary.BigEndian.Uint16(shares[2:]))
			if chrome150Normalize([]uint16{group})[0] != expected.Group || length != expected.Length || len(shares) < 4+length {
				t.Fatal("key share group/order/length differs from capture")
			}
			key := shares[4 : 4+length]
			if !chrome150GREASE(group) {
				if index != 0 && bytes.Equal(previousKeys[group], key) {
					t.Fatalf("group %d reused its key material", group)
				}
				previousKeys[group] = bytes.Clone(key)
			}
			shares = shares[4+length:]
		}
		if len(shares) != 0 {
			t.Fatal("unexpected key_share entry")
		}
		ech := hello.payloads[65037]
		shape := baseline.ECHShape
		if len(ech) != 10+shape.EncapsulatedKeyLength+shape.PayloadLength || ech[0] != 0 || binary.BigEndian.Uint16(ech[1:]) != shape.KDF || binary.BigEndian.Uint16(ech[3:]) != shape.AEAD || int(binary.BigEndian.Uint16(ech[6:])) != shape.EncapsulatedKeyLength || int(binary.BigEndian.Uint16(ech[8+shape.EncapsulatedKeyLength:])) != shape.PayloadLength {
			t.Fatal("GREASE ECH shape differs from capture")
		}
		if index != 0 && (bytes.Equal(previousECH[8:8+shape.EncapsulatedKeyLength], ech[8:8+shape.EncapsulatedKeyLength]) || bytes.Equal(previousECH[10+shape.EncapsulatedKeyLength:], ech[10+shape.EncapsulatedKeyLength:])) {
			t.Fatal("GREASE ECH key or payload reused")
		}
		previousECH = bytes.Clone(ech)
		var groups, points []uint16
		for data := hello.payloads[10][2:]; len(data) >= 2; data = data[2:] {
			groups = append(groups, binary.BigEndian.Uint16(data))
		}
		for _, point := range hello.payloads[11][1:] {
			points = append(points, uint16(point))
		}
		ja3 := fmt.Sprintf("%d,%s,%s,%s,%s", binary.BigEndian.Uint16(wire[9:11]), chrome150JA3Vector(hello.ciphers), chrome150JA3Vector(hello.extensions), chrome150JA3Vector(groups), chrome150JA3Vector(points))
		if ja3 != baseline.JA3 || fmt.Sprintf("%x", md5.Sum([]byte(ja3))) != baseline.JA3Hash {
			t.Fatal("serialized ClientHello JA3 differs from capture baseline")
		}
		var settings, pseudo []string
		for _, setting := range snapshot.Settings[index] {
			settings = append(settings, fmt.Sprintf("%d:%d", setting.ID, setting.Val))
		}
		for _, field := range snapshot.Requests[index].Headers {
			if letter := map[string]string{":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}[field.Name]; letter != "" {
				pseudo = append(pseudo, letter)
			}
		}
		if len(snapshot.Windows) != 2 || snapshot.Windows[index].StreamID != 0 || len(snapshot.Priorities) != 0 {
			t.Fatal("unexpected initial H2 WINDOW_UPDATE or PRIORITY frames")
		}
		akamai := strings.Join(settings, ";") + "|" + strconv.FormatUint(uint64(snapshot.Windows[index].Amount), 10) + "|0|" + strings.Join(pseudo, ",")
		if akamai != baseline.AkamaiFingerprint {
			t.Fatal("HTTP/2 fingerprint differs from capture baseline")
		}
	}
}
