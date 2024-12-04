package scan

import (
	"fmt"
)

type Gobuster struct {
}

func (d *Gobuster) Info(url string) {
	fmt.Println("[+] Running Gobuster on", url)
}

func (d *Gobuster) Configure(c interface{}) {
}

func (d *Gobuster) Run(url string) {

	fmt.Printf("[SCAN %s] Gobuster scan for %s completed\n\n", url)
}
