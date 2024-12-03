package osint

import (
	"fmt"
)

type OsintOpts struct {
	domain   string
	scanPath string
	proxy    string
	dryRun   bool
}

func (opts *OsintOpts) SetDomain(domain string) {
	opts.domain = domain
}

func (opts *OsintOpts) SetScanPath(data string) {
	opts.scanPath = data
}

func (opts *OsintOpts) SetProxy(data string) {
	opts.proxy = data
}

func (opts *OsintOpts) SetDryRun(data bool) {
	opts.dryRun = data
}

func (opts OsintOpts) runGoogleDorks() {

	dorks := Dorks{}
	dorksCfg := make(map[string]interface{})

	dorksOutfile := fmt.Sprintf("%s/dorks_%s.txt", opts.scanPath, opts.domain)
	dorksCfg["outfile"] = dorksOutfile
	dorksCfg["proxy"] = opts.proxy

	dorks.Configure(dorksCfg)
	dorks.Info(opts.domain)
	if !opts.dryRun {
		dorks.Run(opts.domain)
	}
}

func (opts OsintOpts) runAssetfinder() {

}

func (opts OsintOpts) runDnsx() {

}

func (opts OsintOpts) runHttpx() {

}

func (opts OsintOpts) runGowitness() {

}

func (opts OsintOpts) Run() {
	fmt.Printf("\n[OSINT] domain: %s\n\n", opts.domain)

	opts.runGoogleDorks()
	opts.runAssetfinder()
	opts.runDnsx()
	opts.runHttpx()
	opts.runGowitness()

	fmt.Printf("[OSINT %s] done.\n", opts.domain)
}
