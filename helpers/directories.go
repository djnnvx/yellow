package helper

import (
	"fmt"
	"os"
)

func SetUpDirectoryArchitecture(target string) {
	dirname := ReplaceWithHyphen(target)
	fmt.Println("[+] setting up directory architecture for", dirname)

	dirs := []string{
		"scans/infra", "scans/ssl", "scans/screenshots", "scans/nessus",
		"extracted/assets", "extracted/creds", "extracted/code",
		"www/exploits", "www/tools",
	}
	for _, d := range dirs {
		full := dirname + "/" + d
		if err := os.MkdirAll(full, 0775); err != nil {
			fmt.Printf("[!] could not create %s: %v\n", full, err)
		}
	}
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
