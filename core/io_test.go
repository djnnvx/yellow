package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteLines(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  string
	}{
		{name: "normal", lines: []string{"a", "b", "c"}, want: "a\nb\nc\n"},
		{name: "single", lines: []string{"only"}, want: "only\n"},
		{name: "empty", lines: nil, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out.txt")
			if err := WriteLines(path, tt.lines); err != nil {
				t.Fatalf("WriteLines: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestSaveStreamSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	body := "hello world"

	n, err := SaveStream(path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if n != int64(len(body)) {
		t.Errorf("byte count: got %d, want %d", n, len(body))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != body {
		t.Errorf("got %q, want %q", string(got), body)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestSaveStreamRemovesPartialFileOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")

	if _, err := SaveStream(path, errReader{}); err == nil {
		t.Fatal("SaveStream: want error, got nil")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("partial file left behind: stat err = %v, want not-exist", err)
	}
}
