package helper

import (
	"bytes"
	"testing"
)

func TestReadCappedBodyTruncatesOversizedBody(t *testing.T) {
	body, truncated, err := ReadCappedBody(bytes.NewReader(make([]byte, MaxBodySize+1<<20)))
	if err != nil {
		t.Fatalf("ReadCappedBody returned %v", err)
	}
	if !truncated {
		t.Error("oversized body not reported as truncated")
	}
	if len(body) != MaxBodySize {
		t.Errorf("read %d bytes, want the %d byte cap", len(body), MaxBodySize)
	}
}

func TestReadCappedBodyKeepsExactCapIntact(t *testing.T) {
	body, truncated, err := ReadCappedBody(bytes.NewReader(make([]byte, MaxBodySize)))
	if err != nil {
		t.Fatalf("ReadCappedBody returned %v", err)
	}
	if truncated {
		t.Error("body of exactly MaxBodySize reported as truncated")
	}
	if len(body) != MaxBodySize {
		t.Errorf("read %d bytes, want %d", len(body), MaxBodySize)
	}
}

func TestResolveWebTargetFallsBackToHTTP(t *testing.T) {
	probed := []string{}
	unavailable := func(url string) bool {
		probed = append(probed, url)
		return url != "http://example.com"
	}

	got, ok := resolveWebTarget("example.com", false, unavailable)
	if !ok {
		t.Fatalf("host serving plaintext was skipped; probed %v", probed)
	}
	if got != "http://example.com" {
		t.Errorf("got %q, want http://example.com", got)
	}
	if len(probed) != 2 || probed[0] != "https://example.com" {
		t.Errorf("want https probed first then http, got %v", probed)
	}
}

func TestResolveWebTargetPrefersHTTPS(t *testing.T) {
	unavailable := func(string) bool { return false }

	got, ok := resolveWebTarget("example.com", false, unavailable)
	if !ok || got != "https://example.com" {
		t.Errorf("got %q (ok=%v), want https://example.com", got, ok)
	}
}

func TestResolveWebTargetForceInsecureSkipsHTTPS(t *testing.T) {
	probed := []string{}
	unavailable := func(url string) bool {
		probed = append(probed, url)
		return false
	}

	got, ok := resolveWebTarget("example.com", true, unavailable)
	if !ok || got != "http://example.com" {
		t.Errorf("got %q (ok=%v), want http://example.com", got, ok)
	}
	if len(probed) != 1 {
		t.Errorf("force-insecure must not probe https, got %v", probed)
	}
}

func TestResolveWebTargetDeadHost(t *testing.T) {
	unavailable := func(string) bool { return true }

	if got, ok := resolveWebTarget("example.com", false, unavailable); ok {
		t.Errorf("dead host reported alive as %q", got)
	}
}
