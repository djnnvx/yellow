package scan

import (
	"fmt"
)

type WappalyzerGo struct {
}

func (d *WappalyzerGo) Info(url string) {
	fmt.Println("[+] Running WappalyzerGo on", url)
}

func (d *WappalyzerGo) Configure(c interface{}) {
}

func (d *WappalyzerGo) Run(url string) {

	fmt.Printf("[SCAN %s] WappalyzerGo scan for %s completed\n\n", url)
}
