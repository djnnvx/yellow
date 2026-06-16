package core

import (
	"os"
	"strings"
)

// WriteLines writes one entry per line, with a trailing newline unless empty.
func WriteLines(path string, lines []string) error {
	s := strings.Join(lines, "\n")
	if s != "" {
		s += "\n"
	}
	return os.WriteFile(path, []byte(s), 0644)
}
