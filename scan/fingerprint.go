package scan

import (
	"fmt"
	"os"

	"evil.djnn.sh/djnn/yellow/core"
	helper "evil.djnn.sh/djnn/yellow/helpers"
)

/*
   This is a sub-command, based on the scan command.

   However, all it does is to run wappalyzer-go then cvemap on it
   for quick wins.
*/

func (opts *ScanOpts) Fingerprint() {
	fmt.Printf("\n[SCAN] domain: %s\n", opts.Domain)

	fullDomain := "https://" + opts.Domain
	if opts.ForceInsecure {
		fullDomain = "http://" + opts.Domain
	}

	if helper.HasUnavailableWebInterface(fullDomain) {
		fmt.Printf("[FINGERPRINT %s] => no web panel online. skipping\n", opts.Domain)
		return
	}

	pathForDomain := opts.ScanPath + "/" + opts.Domain
	if err := os.MkdirAll(pathForDomain, 0755); err != nil {
		fmt.Printf("[!] fingerprint: could not create %s, skipping %s: %v\n", pathForDomain, opts.Domain, err)
		return
	}

	ctx := opts.context()
	ctx.Domain = fullDomain
	ctx.ScanPath = pathForDomain

	core.RunModules(ctx, []core.Module{&WappalyzerGo{}, &Cvemap{}})
}
