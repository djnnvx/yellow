package osint

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"slices"
	"strings"

	"evil.djnn.sh/djnn/yellow/helpers"
)

type OsintOpts struct {
	domain    string
	scanPath  string
	proxy     string
	dryRun    bool
	rateLimit int32
}

func (opts *OsintOpts) SetRateLimit(data int32) {
	opts.rateLimit = data
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
	dnsxCfg["proxy"] = opts.proxy

	dnsx.Configure(dnsxCfg)
	dnsx.Info(opts.domain)

	if !opts.dryRun {
		dnsx.Run(opts.domain)
	}
}

func (opts OsintOpts) Run() {
	fmt.Printf("\n[OSINT] domain: %s\n\n", opts.domain)

	opts.runGoogleDorks()
	opts.runSubfinder()
	opts.runAssetfinder()
	opts.runDnsx()

	fmt.Printf("\n[OSINT %s] merging aggregated IP addresses together\n", opts.domain)

	asfFilepath := fmt.Sprintf("%s/assetfinder_%s.txt", opts.scanPath, opts.domain)
	dnsxFilepath := fmt.Sprintf("%s/dnsx_%s.json", opts.scanPath, opts.domain)
	sbfOutfile := fmt.Sprintf("%s/subfinder_%s.txt", opts.scanPath, opts.domain)

	domainsFiles := []string{asfFilepath, dnsxFilepath, sbfOutfile}
	var domains []string
	var domainBuffer bytes.Buffer
	for _, file := range domainsFiles {
		newDomains, err := ioutil.ReadFile(file)
		if err != nil {
			panic(err)
		}

		/* check if valid IP address / domain & if it's already in the list */
		lines := strings.Split(strings.ReplaceAll(string(newDomains), "\r\n", "\n"), "\n")
		for _, domain := range lines {

			parsedDomain := strings.Trim(domain, "\t \",")

			// already exists in list
			if slices.Contains(domains, parsedDomain) {
				continue
			}

			// is IP address ?
			addr := net.ParseIP(parsedDomain)

			// does it look like a domain name ? at least one .
			// (hacky, but no need to make it better for now)
			if addr != nil || (!helper.StringHasUnwantedCharacters(parsedDomain) && parsedDomain != "") {
				domains = append(domains, parsedDomain)
				domainBuffer.Write([]byte(string(parsedDomain) + "\n"))
			}
		}
	}

	// now add all assets together, line by line
	uniqueOutfile := fmt.Sprintf("%s/domains_%s.txt", opts.scanPath, opts.domain)
	err := ioutil.WriteFile(uniqueOutfile, domainBuffer.Bytes(), 0644)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[OSINT %s] Registered %v IP addresses and assets.\n", opts.domain, len(domains))
    fmt.Printf("[OSINT %s] Location of unique domain names: %s.\n", opts.domain, uniqueOutfile)
	fmt.Printf("[OSINT %s] done.\n", opts.domain)
}
