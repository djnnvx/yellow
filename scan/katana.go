package scan

import (
	"fmt"
)

type Katana struct {
}

func (d *Katana) Info(url string) {
	fmt.Println("[+] Running Katana on", url)
}

func (d *Katana) Configure(c interface{}) {
}

func (d *Katana) Run(url string) {

	fmt.Printf("[SCAN %s] Katana scan for %s completed\n\n", url)
}
