package scan

import (
	"fmt"
	"os"

	helper "evil.djnn.sh/djnn/yellow/helpers"
)

/*
   This is a sub-command, based on the scan command.

   However, all it does is to run wappalyzer-go then cvemap on it
   for quick wins.
*/

func (opts *ScanOpts) Fingerprint() {
	fmt.Printf("\n[SCAN] domain: %s\n", opts.domain)

	fullDomain := "https://" + opts.domain
	if opts.forceInsecure {
		fullDomain = "http://" + opts.domain
	}

	if !helper.HasUnavailableWebInterface(fullDomain) {
		pathForDomain := opts.scanPath + "/" + opts.domain
		opts.SetScanPath(pathForDomain)

		if err := os.MkdirAll(opts.scanPath, 0755); err != nil {
			fmt.Printf("[!] fingerprint: could not create %s, skipping %s: %v\n", opts.scanPath, opts.domain, err)
			return
		}

		opts.SetDomain(fullDomain)

		opts.RunWappalyzerGo()
		opts.RunCvemap()
	} else {
		fmt.Printf("[FINGERPRINT %s] => no web panel online. skipping\n", opts.domain)
	}
}
