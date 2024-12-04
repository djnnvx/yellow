package scan

import (
	"fmt"
)

type Httpx struct {
}

func (d *Httpx) Info(url string) {
	fmt.Println("[+] Running Httpx on", url)
}

func (d *Httpx) Configure(c interface{}) {
}

func (d *Httpx) Run(url string) {

	fmt.Printf("[SCAN %s] Httpx scan for %s completed\n\n", url)
}
