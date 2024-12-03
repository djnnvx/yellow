package helper

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

type FileScanner struct {
	io.Closer
	*bufio.Scanner
}

func LoadTargetFile(targetPath string) *FileScanner {
	file, err := os.Open(targetPath)
	if err != nil {
		fmt.Printf("%v, %+v", err, targetPath)
	}

	scanner := bufio.NewScanner(file)
	body, err := ioutil.ReadFile(targetPath)
	if err != nil {
		fmt.Printf("%v, %+v", err, targetPath)
	}

	fmt.Println("Loaded target: \n%v", strings.Replace(string(body), "\n", ", ", -1))

	return &FileScanner{file, scanner}
}
