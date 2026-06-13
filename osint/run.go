package osint

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"evil.djnn.sh/djnn/yellow/helpers"
)

type OsintOpts struct {
	domain     string
	scanPath   string
	proxy      string
	dryRun     bool
	rateLimit  int32
	emailsFile string
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

func (opts *OsintOpts) SetEmailsFile(data string) {
	opts.emailsFile = data
}

func (opts OsintOpts) RunCleanup() {
	fmt.Println("[+] cleaning up...")

	/* remove superfluous files */
	asfFilepath := fmt.Sprintf("%s/assetfinder.txt", opts.scanPath)
	sbfOutfile := fmt.Sprintf("%s/subfinder.txt", opts.scanPath)

	for _, f := range []string{asfFilepath, sbfOutfile} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			fmt.Printf("[!] cleanup: could not remove %s: %v\n", f, err)
		}
	}
}

func (opts OsintOpts) runShodan(domains []string) {

	shodanExec := Shodan{}
	shodanCfg := make(map[string]any)

	shodanCfg["outfile"] = fmt.Sprintf("%s/shodan.txt", opts.scanPath)
	shodanExec.Configure(shodanCfg)

	shodanExec.Info(opts.domain)
	if opts.dryRun || !shodanExec.ShouldRun() {
		return
	}

	for _, d := range domains {
		shodanExec.Run(d)
	}
}

func (opts OsintOpts) runGoogleDorks() {

	dorks := Dorks{}
	dorksCfg := make(map[string]any)

	dorksOutfile := fmt.Sprintf("%s/dorks.txt", opts.scanPath)
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
	sbfCfg := make(map[string]any)

	sbfOutfile := fmt.Sprintf("%s/subfinder.txt", opts.scanPath)
	sbfCfg["outfile"] = sbfOutfile

	sbf.Configure(sbfCfg)
	sbf.Info(opts.domain)

	if !opts.dryRun {
		sbf.Run(opts.domain)
	}

}

func (opts OsintOpts) runAssetfinder() {
	asf := Assetfinder{}
	asfCfg := make(map[string]any)

	asfOutfile := fmt.Sprintf("%s/assetfinder.txt", opts.scanPath)

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
	dnsxCfg := make(map[string]any)

	dnsxOutfile := fmt.Sprintf("%s/dnsx.json", opts.scanPath)
	dnsxCfg["outfile"] = dnsxOutfile
	dnsxCfg["proxy"] = opts.proxy

	dnsx.Configure(dnsxCfg)
	dnsx.Info(opts.domain)

	if !opts.dryRun {
		dnsx.Run(opts.domain)
	}
}

func (opts OsintOpts) runLeaker() {
	leaker := Leaker{}
	leakerCfg := make(map[string]any)

	leakerOutfile := fmt.Sprintf("%s/leaks.txt", opts.scanPath)
	leakerCfg["outfile"] = leakerOutfile
	leakerCfg["emailsFile"] = opts.emailsFile
	leakerCfg["proxy"] = opts.proxy

	leaker.Configure(leakerCfg)
	leaker.Info(opts.domain)

	if opts.dryRun || !leaker.ShouldRun() {
		return
	}

	leaker.Run(opts.domain)
}

func (opts OsintOpts) Run() {
	fmt.Printf("\n[OSINT] domain: %s\n\n", opts.domain)

	opts.runGoogleDorks()
	opts.runSubfinder()
	opts.runAssetfinder()
	opts.runDnsx()
	opts.runLeaker()

	asfFilepath := fmt.Sprintf("%s/assetfinder.txt", opts.scanPath)
	dnsxFilepath := fmt.Sprintf("%s/dnsx.json", opts.scanPath)
	sbfOutfile := fmt.Sprintf("%s/subfinder.txt", opts.scanPath)

	domainsFiles := []string{asfFilepath, dnsxFilepath, sbfOutfile}
	var domains []string
	var domainBuffer bytes.Buffer
	for _, file := range domainsFiles {
		newDomains, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("[!] osint: could not read %s, skipping: %v\n", file, err)
			continue
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
			if addr != nil || (!helper.StringHasUnwantedCharactersForDomainName(parsedDomain) && parsedDomain != "") {
				domains = append(domains, parsedDomain)
				domainBuffer.Write([]byte(string(parsedDomain) + "\n"))
			}
		}
	}

	opts.runShodan(domains)

	// now add all assets together, line by line
	uniqueOutfile := fmt.Sprintf("%s/domains.txt", opts.scanPath)
	if err := os.WriteFile(uniqueOutfile, domainBuffer.Bytes(), 0644); err != nil {
		fmt.Printf("[!] osint: could not write %s: %v\n", uniqueOutfile, err)
		return
	}

	fmt.Printf("[OSINT %s] Registered %v IP addresses and assets.\n", opts.domain, len(domains))
	fmt.Printf("[OSINT %s] Location of unique domain names: %s\n", opts.domain, uniqueOutfile)
	fmt.Printf("[OSINT %s] done.\n", opts.domain)

	opts.RunCleanup()
}
