package scan

import (
	"fmt"
)

type Gowitness struct {
}

func (d *Gowitness) Info(url string) {
	fmt.Println("[+] Running Gowitness on", url)
}

func (d *Gowitness) Configure(c interface{}) {
}

func (d *Gowitness) Run(url string) {

	fmt.Printf("[SCAN %s] Gowitness scan for %s completed\n\n", url)
}
