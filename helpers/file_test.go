package helper

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// a line past bufio.Scanner's 64KB cap used to end the run silently
func TestLoadTargetFileKeepsGoingPastALongLine(t *testing.T) {
	long := strings.Repeat("A", 70_000)
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(long+"\n\nexample.com\n  example.org  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	f := LoadTargetFile(path)
	defer f.Close()

	got := slices.Collect(f.Lines())
	want := []string{long, "example.com", "example.org"}
	if !slices.Equal(got, want) {
		t.Errorf("got %d targets %q, want %d", len(got), truncate(got), len(want))
	}
}

func truncate(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if len(l) > 20 {
			l = l[:20] + "..."
		}
		out[i] = l
	}
	return out
}
