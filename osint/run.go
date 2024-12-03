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

func (opts OsintOpts) runSubfinder() {
	sbf := Subfinder{}
	sbfCfg := make(map[string]interface{})

	sbfOutfile := fmt.Sprintf("%s/subfinder_%s.txt", opts.scanPath, opts.domain)
	sbfCfg["outfile"] = sbfOutfile

	sbf.Configure(sbfCfg)
	sbf.Info(opts.domain)

	if !opts.dryRun {
		sbf.Run(opts.domain)
	}

}

func (opts OsintOpts) runAssetfinder() {
	asf := Assetfinder{}
	asfCfg := make(map[string]interface{})

	asfOutfile := fmt.Sprintf("%s/assetfinder_%s.txt", opts.scanPath, opts.domain)

	asfCfg["scanPath"] = opts.scanPath
	asfCfg["outfile"] = asfOutfile

	asf.Configure(asfCfg)
	asf.Info(opts.domain)

	if !opts.dryRun {
		asf.Run(opts.domain)
	}
}

func (opts OsintOpts) runDnsx() {
	dnsx := Dnsx{}
	dnsxCfg := make(map[string]interface{})

	dnsxOutfile := fmt.Sprintf("%s/dnsx_%s.json", opts.scanPath, opts.domain)
	dnsxCfg["outfile"] = dnsxOutfile

	dnsx.Configure(dnsxCfg)
	dnsx.Info(opts.domain)

	if !opts.dryRun {
		dnsx.Run(opts.domain)
	}
}

func (opts OsintOpts) runHttpx() {

}

func (opts OsintOpts) runGowitness() {

}

func (opts OsintOpts) Run() {
	fmt.Printf("\n[OSINT] domain: %s\n\n", opts.domain)

	opts.runGoogleDorks()
	opts.runSubfinder()
	opts.runAssetfinder()
	opts.runDnsx()
	opts.runHttpx()
	opts.runGowitness()

	fmt.Printf("[OSINT %s] done.\n", opts.domain)
}
