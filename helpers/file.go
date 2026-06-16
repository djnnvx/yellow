package helper

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

type FileScanner struct {
	io.Closer
	*bufio.Scanner
}

func LoadTargetFile(targetPath string) *FileScanner {
	file, err := os.Open(targetPath)
	if err != nil {
		fmt.Printf("[!] Could not open target file %q: %v\n", targetPath, err)
		os.Exit(1)
	}

	fmt.Println("[+] Loaded targets from", targetPath)
	return &FileScanner{file, bufio.NewScanner(file)}
}
