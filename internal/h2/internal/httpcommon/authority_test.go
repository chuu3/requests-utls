package httpcommon

import "testing"

func TestServerRequestAuthorityValidation(t *testing.T) {
	for _, tc := range []struct {
		name, authority     string
		hosts               []string
		wantHost, wantError string
	}{
		{"authority only", "example.com", nil, "example.com", ""},
		{"matching host", "example.com", []string{"example.com"}, "example.com", ""},
		{"host fallback", "", []string{"example.com"}, "example.com", ""},
		{"mismatch", "example.com", []string{"other.example"}, "", "authority_host_mismatch"},
		{"duplicate", "example.com", []string{"example.com", "example.com"}, "", "multiple_host_headers"},
		{"invalid authority", "bad host", nil, "", "invalid_authority"},
		{"userinfo fallback", "", []string{"user@example.com"}, "", "userinfo_in_authority"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := map[string][]string{}
			if tc.hosts != nil {
				h["Host"] = tc.hosts
			}
			r := NewServerRequest(ServerRequestParam{Method: "GET", Scheme: "https", Path: "/", Authority: tc.authority, Header: h})
			if r.InvalidReason != tc.wantError {
				t.Fatalf("error = %q, want %q", r.InvalidReason, tc.wantError)
			}
			if tc.wantError != "" {
				return
			}
			if r.Host != tc.wantHost {
				t.Fatalf("Host = %q, want %q", r.Host, tc.wantHost)
			}
			if _, present := h["Host"]; present {
				t.Fatal("Host must be removed from regular headers")
			}
		})
	}
}
