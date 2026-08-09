package helper

import (
	"bufio"
	"fmt"
	"io"
	"iter"
	"os"
	"strings"
)

type FileScanner struct {
	io.Closer
	reader *bufio.Reader
	path   string
}

func LoadTargetFile(targetPath string) *FileScanner {
	file, err := os.Open(targetPath)
	if err != nil {
		fmt.Printf("[!] Could not open target file %q: %v\n", targetPath, err)
		os.Exit(1)
	}

	fmt.Println("[+] Loaded targets from", targetPath)
	return &FileScanner{file, bufio.NewReader(file), targetPath}
}

// Lines streams the file with no line-length cap. A read failure exits instead
// of ending the run short with nothing to show for it.
func (f *FileScanner) Lines() iter.Seq[string] {
	return func(yield func(string) bool) {
		for {
			line, err := f.reader.ReadString('\n')
			if t := strings.TrimSpace(line); t != "" && !yield(t) {
				return
			}
			if err != nil {
				if err != io.EOF {
					fmt.Printf("[!] Could not read target file %q: %v\n", f.path, err)
					os.Exit(1)
				}
				return
			}
		}
	}
}
