package osint

import (
	"fmt"
)

type Gowitness struct {
}

func (h *Gowitness) Info(url string) {
	fmt.Println("[+] Running gowitness on %s", url)
}

func (h *Gowitness) Configure(c interface{}) {

}

func (h *Gowitness) Run(domain string) {
	fmt.Printf("[OSINT %s] gowitness completed.", domain)
}
