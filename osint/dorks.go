package osint

import (
	"fmt"

	dorks "github.com/bogdzn/gork/cmd"
)

type Dorks struct {
	outfile string
	proxy   string
}

func (d *Dorks) Info(url string) {
	fmt.Println("[+] Running dorks on", url)
}

func (d *Dorks) Configure(c any) {
	d.outfile = c.(map[string]any)["outfile"].(string)
	d.proxy = c.(map[string]any)["proxy"].(string)
}

func (d *Dorks) Run(domain string) {
	opts := &dorks.Options{
		Proxy:         d.proxy,
		Outfile:       d.outfile,
		AppendResults: false,
		Extensions:    dorks.DefaultFileExtensions(),
		Exclusions:    dorks.DefaultExclusions(),
		UserAgent:     dorks.DefaultUserAgent(),
		Target:        domain,
	}

	dorks.Run(opts)
	fmt.Printf("[OSINT %s] Dorks are stored in %s\n\n", domain, d.outfile)
}
