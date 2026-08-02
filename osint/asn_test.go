package osint

import (
	"errors"
	"net"
	"testing"
)

func TestParseCymruOrigin(t *testing.T) {
	got, ok := parseCymruOrigin("15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
	if !ok {
		t.Fatal("real cymru record failed to parse")
	}
	want := asnOrigin{ASN: "15169", Prefix: "8.8.8.0/24", Country: "US", Registry: "arin"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseCymruOriginMultiOrigin(t *testing.T) {
	got, ok := parseCymruOrigin("1234 5678 | 194.204.0.0/18 | EE | ripencc | 1995-12-04")
	if !ok || got.ASN != "1234" {
		t.Errorf("multiply-originated prefix: got ASN %q, want 1234", got.ASN)
	}
}

func TestParseCymruOriginRejectsJunk(t *testing.T) {
	for _, txt := range []string{"", "   ", "no pipes here", " | 1.2.3.0/24"} {
		if _, ok := parseCymruOrigin(txt); ok {
			t.Errorf("parsed junk %q as a record", txt)
		}
	}
}

func TestParseShadowserverOriginFieldOrder(t *testing.T) {
	got, ok := parseShadowserverOrigin("15169 | 8.8.8.0/24 | AS15169 | US | Google LLC")
	if !ok {
		t.Fatal("real shadowserver record failed to parse")
	}
	// field order differs from cymru: org is index 4, country index 3
	want := asnOrigin{ASN: "15169", Prefix: "8.8.8.0/24", Country: "US", Org: "Google LLC"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseCymruASName(t *testing.T) {
	// AS name itself contains hyphens and commas
	got := parseCymruASName("20473 | US | arin | 2001-05-11 | AS-VULTR - The Constant Company, LLC, US")
	if got != "AS-VULTR - The Constant Company, LLC, US" {
		t.Errorf("got %q", got)
	}
	if parseCymruASName("20473 | US | arin") != "" {
		t.Error("short record should yield no name")
	}
}

func TestReverseIPv4(t *testing.T) {
	if got := reverseIPv4("1.2.3.4"); got != "4.3.2.1" {
		t.Errorf("got %q, want 4.3.2.1", got)
	}
	if got := reverseIPv4("2001:4860::1"); got != "" {
		t.Errorf("ipv6 should yield empty, got %q", got)
	}
}

func TestIsHostingProviderCatchesVultr(t *testing.T) {
	// RFC 5737 documentation range: cdncheck does not match it, so only the
	// AS-name keyword can flag this. Same situation as Vultr in the wild.
	doc := net.ParseIP("192.0.2.1")
	if LookupCDNMatches(doc) {
		t.Skip("cdncheck now covers the documentation range; keyword path untestable here")
	}
	if !isHostingProvider("AS-VULTR - The Constant Company, LLC, US", doc) {
		t.Error("Vultr not flagged as hosting provider")
	}
	if isHostingProvider("EXAMPLE-CORP - Example Bank Inc", doc) {
		t.Error("a self-hosted org was wrongly flagged as a provider")
	}
}

func TestOriginFailsOverToSecondProvider(t *testing.T) {
	calls := []string{}
	a := &ASN{
		lookupTXT: func(name string) ([]string, error) {
			calls = append(calls, name)
			if name == "4.3.2.1.origin.asn.cymru.com" {
				return nil, errors.New("primary down")
			}
			return []string{"15169 | 8.8.8.0/24 | AS15169 | US | Google LLC"}, nil
		},
		providers: asnProviders,
	}

	origin, source, ok := a.origin("1.2.3.4")
	if !ok {
		t.Fatalf("failover produced no record; queried %v", calls)
	}
	if source != "shadowserver" {
		t.Errorf("source = %q, want shadowserver", source)
	}
	if origin.ASN != "15169" || origin.Prefix != "8.8.8.0/24" || origin.Org != "Google LLC" {
		t.Errorf("bad failover record: %+v", origin)
	}
}

func TestOriginAllProvidersDown(t *testing.T) {
	a := &ASN{
		lookupTXT: func(string) ([]string, error) { return nil, errors.New("down") },
		providers: asnProviders,
	}
	if _, _, ok := a.origin("1.2.3.4"); ok {
		t.Error("all providers down must yield no record, not a bogus one")
	}
}

func TestOriginEmptyAnswerIsNotARecord(t *testing.T) {
	a := &ASN{
		lookupTXT: func(string) ([]string, error) { return []string{""}, nil },
		providers: asnProviders,
	}
	if _, _, ok := a.origin("192.168.1.1"); ok {
		t.Error("private IP with empty TXT must yield no record")
	}
}

func LookupCDNMatches(ip net.IP) bool {
	return isHostingProvider("", ip)
}
