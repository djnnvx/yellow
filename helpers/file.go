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

	scanner := bufio.NewScanner(file)
	body, err := os.ReadFile(targetPath)
	if err != nil {
		fmt.Printf("%v, %+v", err, targetPath)
	}

	fmt.Println("[+] Loaded targets: \n", string(body))

	return &FileScanner{file, scanner}
}
