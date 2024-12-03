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

	_ = os.MkdirAll(dirname, 0775)
	CreateDirectory(dirname, []Folder{
		{
			Name:     "scans",
			Children: FolderNameFactory("nmap", "infra", "web", "ssl", "screenshots", "nessus"),
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
	if err == nil {
		return true
	}
	return false
}

func CreateDirectory(base string, folders []Folder) {
	for _, f := range folders {
		current := fmt.Sprintf("%s/%s", base, f.Name)
		_ = os.Mkdir(current, 0775)
		if len(f.Children) != 0 {
			CreateDirectory(current, f.Children)
		}
	}
}

func FolderNameFactory(names ...string) []Folder {
	f := make([]Folder, len(names))
	for _, name := range names {
		f = append(f, Folder{Name: name})
	}

	return f
}
