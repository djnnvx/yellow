package helper

import (
	"fmt"
	"os"
)

type Folder struct {
	Name     string
	Children []Folder
}

func CreateDirectory(base string, folders []Folder) {
	for _, f := range folders {
		current := fmt.Sprintf("%s/%s", base, f.Name)
		if e := os.Mkdir(current, 0775); e != nil {
			fmt.Println(e)
		}
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
