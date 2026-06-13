package osint

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"evil.djnn.sh/djnn/yellow/core"
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

// context builds a Context from the current options.
func (opts *OsintOpts) context() *core.Context {
	return &core.Context{
		Domain:     opts.domain,
		ScanPath:   opts.scanPath,
		Proxy:      opts.proxy,
		DryRun:     opts.dryRun,
		RateLimit:  opts.rateLimit,
		EmailsFile: opts.emailsFile,
	}
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

func (opts *OsintOpts) Run() {
	fmt.Printf("\n[OSINT] domain: %s\n\n", opts.domain)

	ctx := opts.context()

	core.RunModules(ctx, []core.Module{
		&Dorks{},
		&Subfinder{},
		&Assetfinder{},
		&Dnsx{},
		&Leaker{},
	})

	// aggregate the assets the enumeration modules wrote, then let shodan
	// consume the unique list.
	domains, buf := opts.aggregateDomains()
	ctx.Domains = domains

	core.RunModules(ctx, []core.Module{&Shodan{}})

	uniqueOutfile := fmt.Sprintf("%s/domains.txt", opts.scanPath)
	if err := os.WriteFile(uniqueOutfile, buf, 0644); err != nil {
		fmt.Printf("[!] osint: could not write %s: %v\n", uniqueOutfile, err)
		return
	}

	fmt.Printf("[OSINT %s] Registered %v IP addresses and assets.\n", opts.domain, len(domains))
	fmt.Printf("[OSINT %s] Location of unique domain names: %s\n", opts.domain, uniqueOutfile)
	fmt.Printf("[OSINT %s] done.\n", opts.domain)

	opts.RunCleanup()
}

// aggregateDomains reads the asset files written by the enumeration modules,
// keeps valid (and unique) IPs and domain names, and returns the unique list
// together with a newline-joined buffer ready to be written to disk.
func (opts *OsintOpts) aggregateDomains() ([]string, []byte) {
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

		lines := strings.Split(strings.ReplaceAll(string(newDomains), "\r\n", "\n"), "\n")
		for _, domain := range lines {
			parsedDomain := strings.Trim(domain, "\t \",")

			// already exists in list
			if slices.Contains(domains, parsedDomain) {
				continue
			}

			// is it a valid IP address, or does it at least look like a domain?
			// (hacky, but no need to make it better for now)
			addr := net.ParseIP(parsedDomain)
			if addr != nil || (!helper.StringHasUnwantedCharactersForDomainName(parsedDomain) && parsedDomain != "") {
				domains = append(domains, parsedDomain)
				domainBuffer.WriteString(parsedDomain + "\n")
			}
		}
	}

	return domains, domainBuffer.Bytes()
}
