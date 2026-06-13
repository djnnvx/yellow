package scan

import (
	"fmt"
	"os"

	"evil.djnn.sh/djnn/yellow/core"
	"evil.djnn.sh/djnn/yellow/helpers"
)

type ScanOpts struct {
	domain        string
	scanPath      string
	proxy         string
	dryRun        bool
	rateLimit     int32
	wordlistPath  string
	forceInsecure bool
	gobuster      bool
	portScan      bool
	ports         string
	nuclei        bool
}

func (opts *ScanOpts) SetGobuster(data bool) {
	opts.gobuster = data
}

func (opts *ScanOpts) SetForceInsecure(data bool) {
	opts.forceInsecure = data
}

func (opts *ScanOpts) SetWordlistPath(data string) {
	opts.wordlistPath = data
}

func (opts *ScanOpts) SetRateLimit(data int32) {
	opts.rateLimit = data
}

func (opts *ScanOpts) SetDomain(data string) {
	opts.domain = data
}

func (opts *ScanOpts) SetScanPath(data string) {
	opts.scanPath = data
}

func (opts *ScanOpts) SetProxy(data string) {
	opts.proxy = data
}

func (opts *ScanOpts) SetDryRun(data bool) {
	opts.dryRun = data
}

func (opts *ScanOpts) SetPortScan(data bool) {
	opts.portScan = data
}

func (opts *ScanOpts) SetPorts(data string) {
	opts.ports = data
}

func (opts *ScanOpts) SetNuclei(data bool) {
	opts.nuclei = data
}

// context builds a per-target Context from the current options.
func (opts *ScanOpts) context() *core.Context {
	return &core.Context{
		Domain:    opts.domain,
		ScanPath:  opts.scanPath,
		Proxy:     opts.proxy,
		DryRun:    opts.dryRun,
		RateLimit: opts.rateLimit,
		Wordlist:  opts.wordlistPath,
		Insecure:  opts.forceInsecure,
	}
}

// webModules is the ordered web-scan pipeline. Gobuster is appended unless
// directory bruteforcing was disabled.
func (opts *ScanOpts) webModules() []core.Module {
	modules := []core.Module{
		&Sitemap{},
		&RobotsTxt{},
		&Tlsx{},
		&WappalyzerGo{},
		&Cvemap{},
		&Httpx{},
	}
	if opts.nuclei {
		modules = append(modules, &Nuclei{})
	}
	if opts.gobuster {
		modules = append(modules, &Gobuster{})
	}
	return modules
}

func (opts *ScanOpts) Run() {
	fmt.Printf("\n[SCAN] domain: %s\n", opts.domain)

	fullDomain := "https://" + opts.domain
	if opts.forceInsecure {
		fullDomain = "http://" + opts.domain
	}

	if opts.portScan {
		opts.runPortScan()
	}

	if helper.HasUnavailableWebInterface(fullDomain) {
		fmt.Printf("[SCAN %s] => no web panel online. skipping\n", opts.domain)
		return
	}

	fmt.Printf("[SCAN %s] web panel online....running web scans\n", opts.domain)

	/* per-domain output dir; setting opts.scanPath directly would nest dirs */
	pathForDomain := opts.scanPath + "/" + opts.domain
	if err := os.MkdirAll(pathForDomain, 0755); err != nil {
		fmt.Printf("[!] scan: could not create %s, skipping %s: %v\n", pathForDomain, opts.domain, err)
		return
	}

	ctx := opts.context()
	ctx.Domain = fullDomain
	ctx.ScanPath = pathForDomain

	core.RunModules(ctx, opts.webModules())
}
