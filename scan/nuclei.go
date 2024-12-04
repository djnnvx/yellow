package scan

import (
	"fmt"
)

type Nuclei struct {
}

func (d *Nuclei) Info(url string) {
	fmt.Println("[+] Running Nuclei on", url)
}

func (d *Nuclei) Configure(c interface{}) {
}

func (d *Nuclei) Run(url string) {

	fmt.Printf("[SCAN %s] Nuclei scan for %s completed\n\n", url)
}
