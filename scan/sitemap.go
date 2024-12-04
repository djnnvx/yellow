package scan

import (
	"fmt"
)

type Sitemap struct {
}

func (d *Sitemap) Info(url string) {
	fmt.Println("[+] Running Sitemap on", url)
}

func (d *Sitemap) Configure(c interface{}) {
}

func (d *Sitemap) Run(url string) {

	fmt.Printf("[SCAN %s] Sitemap scan for %s completed\n\n", url)
}
