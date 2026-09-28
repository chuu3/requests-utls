package http2

import "testing"

func TestAuthorityAddrLookupProfile(t *testing.T) {
	for _, tc := range []struct{ authority, want string }{
		{"BÜCHER.example", "xn--bcher-kva.example:443"},
		{"ｅｘａｍｐｌｅ.com:8443", "example.com:8443"},
		{"EXAMPLE.com", "EXAMPLE.com:443"},
		{"under_score.example", "under_score.example:443"},
		{"[::1]", "[::1]:443"},
		{"[::1]:8443", "[::1]:8443"},
	} {
		t.Run(tc.authority, func(t *testing.T) {
			if got := authorityAddr("https", tc.authority); got != tc.want {
				t.Fatalf("authorityAddr = %q, want %q", got, tc.want)
			}
		})
	}
}
