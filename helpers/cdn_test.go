package helper

import (
	"net"
	"testing"
)

func TestSkipPortScan(t *testing.T) {
	tests := []struct {
		name string
		info *CDNInfo
		want bool
	}{
		{"no match", nil, false},
		{"gce compute filed under cdn/google", &CDNInfo{Type: "cdn", Provider: "google"}, false},
		{"cloudfront edge", &CDNInfo{Type: "cdn", Provider: "cloudfront"}, false},
		{"aws cloud", &CDNInfo{Type: "cloud", Provider: "aws"}, false},
		{"cloudflare waf", &CDNInfo{Type: "waf", Provider: "cloudflare"}, true},
		{"incapsula waf", &CDNInfo{Type: "waf", Provider: "incapsula"}, true},
	}

	for _, tt := range tests {
		if got := SkipPortScan(tt.info); got != tt.want {
			t.Errorf("%s: SkipPortScan(%+v) = %v, want %v", tt.name, tt.info, got, tt.want)
		}
	}
}

func TestLookupCDNClassifiesRealRanges(t *testing.T) {
	tests := []struct {
		ip       string
		wantType string
	}{
		{"1.1.1.1", "waf"},    // cloudflare
		{"104.16.1.1", "waf"}, // cloudflare
		{"8.8.8.8", "cdn"},    // google, must NOT be skipped
		{"192.168.1.1", ""},   // private, no match
	}

	for _, tt := range tests {
		got := LookupCDN(net.ParseIP(tt.ip))
		if tt.wantType == "" {
			if got != nil {
				t.Errorf("%s: want no match, got %+v", tt.ip, got)
			}
			continue
		}
		if got == nil || got.Type != tt.wantType {
			t.Errorf("%s: want type %q, got %+v", tt.ip, tt.wantType, got)
		}
	}
}

func TestGCEOriginIsNeverSkipped(t *testing.T) {
	// google ranges cover ordinary compute, so a real origin lives here
	if SkipPortScan(LookupCDN(net.ParseIP("8.8.8.8"))) {
		t.Fatal("GCE origin would be skipped, losing real attack surface")
	}
	if !SkipPortScan(LookupCDN(net.ParseIP("1.1.1.1"))) {
		t.Fatal("cloudflare edge should be skipped")
	}
}
