package helper

import (
	"fmt"
	"os"
)

type Folder struct {
	Name     string
	Children []Folder
}

func SetUpDirectoryArchitecture(target string) {
	dirname := ReplaceWithHyphen(target)
	fmt.Println("[+] setting up directory architecture for", dirname)

	if err := os.MkdirAll(dirname, 0775); err != nil {
		fmt.Printf("[!] could not create %s: %v\n", dirname, err)
		return
	}
	CreateDirectory(dirname, []Folder{
		{
			Name:     "scans",
			Children: FolderNameFactory("infra", "ssl", "screenshots", "nessus"),
		},
		{
			Name:     "extracted",
			Children: FolderNameFactory("assets", "creds", "code"),
		},
		{
			Name:     "www",
			Children: FolderNameFactory("exploits", "tools"),
		},
	})
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func CreateDirectory(base string, folders []Folder) {
	for _, f := range folders {
		current := fmt.Sprintf("%s/%s", base, f.Name)
		if err := os.Mkdir(current, 0775); err != nil && !os.IsExist(err) {
			fmt.Printf("[!] could not create %s: %v\n", current, err)
		}
		if len(f.Children) != 0 {
			CreateDirectory(current, f.Children)
		}
	}
}

func FolderNameFactory(names ...string) []Folder {
	f := make([]Folder, 0, len(names))
	for _, name := range names {
		f = append(f, Folder{Name: name})
	}

	return f
}
