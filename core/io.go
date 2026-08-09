package core

import (
	"io"
	"os"
	"strings"
)

// SaveStream writes r to path without holding it in memory.
func SaveStream(path string, r io.Reader) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// WriteLines writes one entry per line, with a trailing newline unless empty.
func WriteLines(path string, lines []string) error {
	s := strings.Join(lines, "\n")
	if s != "" {
		s += "\n"
	}
	return os.WriteFile(path, []byte(s), 0644)
}
