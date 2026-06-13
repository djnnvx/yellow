package osint

import (
	"fmt"
	"net"
	"net/url"
	"os"
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
		&Gau{},
		&Leaker{},
	})

	ctx.Domains = opts.aggregateDomains()

	core.RunModules(ctx, []core.Module{&Alterx{}, &Shodan{}})

	uniqueOutfile := fmt.Sprintf("%s/domains.txt", opts.scanPath)
	content := strings.Join(ctx.Domains, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(uniqueOutfile, []byte(content), 0644); err != nil {
		fmt.Printf("[!] osint: could not write %s: %v\n", uniqueOutfile, err)
		return
	}

	fmt.Printf("[OSINT %s] Registered %v IP addresses and assets.\n", opts.domain, len(ctx.Domains))
	fmt.Printf("[OSINT %s] Location of unique domain names: %s\n", opts.domain, uniqueOutfile)
	fmt.Printf("[OSINT %s] done.\n", opts.domain)

	opts.RunCleanup()
}

func (opts *OsintOpts) aggregateDomains() []string {
	var domains []string
	seen := map[string]struct{}{}

	add := func(candidate string) {
		candidate = strings.Trim(candidate, "\t \",")
		if candidate == "" {
			return
		}
		if _, ok := seen[candidate]; ok {
			return
		}
		ip := net.ParseIP(candidate)
		if (ip != nil && ip.To4() != nil) || (ip == nil && !helper.StringHasUnwantedCharactersForDomainName(candidate)) {
			seen[candidate] = struct{}{}
			domains = append(domains, candidate)
		}
	}

	asfFilepath := fmt.Sprintf("%s/assetfinder.txt", opts.scanPath)
	dnsxFilepath := fmt.Sprintf("%s/dnsx.json", opts.scanPath)
	sbfOutfile := fmt.Sprintf("%s/subfinder.txt", opts.scanPath)

	for _, file := range []string{asfFilepath, dnsxFilepath, sbfOutfile} {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("[!] osint: could not read %s, skipping: %v\n", file, err)
			continue
		}
		for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			add(line)
		}
	}

	urlsFile := fmt.Sprintf("%s/urls.txt", opts.scanPath)
	if data, err := os.ReadFile(urlsFile); err == nil {
		for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			if u, err := url.Parse(strings.TrimSpace(line)); err == nil {
				add(u.Hostname())
			}
		}
	}

	return domains
}
