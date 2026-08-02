package scan

import (
	"reflect"
	"testing"
)

func TestMergePortResultsKeepsUnfingerprintedPorts(t *testing.T) {
	open := []int{22, 80, 443}
	enriched := map[int]PortResult{
		22: {Port: 22, Proto: "tcp", Service: "ssh"},
		80: {Port: 80, Proto: "tcp", Service: "http", Version: "OpenBSD httpd"},
	}

	got := mergePortResults(open, enriched)

	if len(got) != len(open) {
		t.Fatalf("dropped open ports: got %d results, want %d (%v)", len(got), len(open), got)
	}
	want := []PortResult{
		{Port: 22, Proto: "tcp", Service: "ssh"},
		{Port: 80, Proto: "tcp", Service: "http", Version: "OpenBSD httpd"},
		{Port: 443, Proto: "tcp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestMergePortResultsNoFingerprints(t *testing.T) {
	got := mergePortResults([]int{8080}, map[int]PortResult{})
	want := []PortResult{{Port: 8080, Proto: "tcp"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		spec    string
		want    []int
		wantErr bool
	}{
		{spec: "22,80,443", want: []int{22, 80, 443}},
		{spec: "80-83", want: []int{80, 81, 82, 83}},
		{spec: "22, 100-102", want: []int{22, 100, 101, 102}},
		{spec: "443-443", want: []int{443}},
		{spec: "100-80", wantErr: true},
		{spec: "http", wantErr: true},
		{spec: "1-x", wantErr: true},
	}

	for _, tt := range tests {
		got, err := parsePorts(tt.spec)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parsePorts(%q): want error, got %v", tt.spec, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePorts(%q): unexpected error %v", tt.spec, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
		}
	}
}
