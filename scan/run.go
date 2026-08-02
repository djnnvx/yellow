package scan

import (
	"fmt"
	"os"

	"evil.djnn.sh/djnn/yellow/core"
	"evil.djnn.sh/djnn/yellow/helpers"
)

type ScanOpts struct {
	Domain        string
	ScanPath      string
	Proxy         string
	DryRun        bool
	RateLimit     int32
	WordlistPath  string
	ForceInsecure bool
	Gobuster      bool
	PortScan      bool
	Ports         string
	Nuclei        bool
}

// context builds a per-target Context from the current options.
func (opts *ScanOpts) context() *core.Context {
	return &core.Context{
		Domain:    opts.Domain,
		ScanPath:  opts.ScanPath,
		Proxy:     opts.Proxy,
		DryRun:    opts.DryRun,
		RateLimit: opts.RateLimit,
		Wordlist:  opts.WordlistPath,
		Insecure:  opts.ForceInsecure,
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
	if opts.Nuclei {
		modules = append(modules, &Nuclei{})
	}
	if opts.Gobuster {
		modules = append(modules, &Gobuster{})
	}
	return modules
}

func (opts *ScanOpts) Run() {
	fmt.Printf("\n[SCAN] domain: %s\n", opts.Domain)

	if opts.PortScan {
		opts.runPortScan()
	}

	fullDomain, ok := helper.ResolveWebTarget(opts.Domain, opts.ForceInsecure)
	if !ok {
		fmt.Printf("[SCAN %s] => no web panel online. skipping\n", opts.Domain)
		return
	}

	fmt.Printf("[SCAN %s] web panel online (%s)....running web scans\n", opts.Domain, fullDomain)

	/* per-domain output dir; setting opts.ScanPath directly would nest dirs */
	pathForDomain := opts.ScanPath + "/" + opts.Domain
	if err := os.MkdirAll(pathForDomain, 0755); err != nil {
		fmt.Printf("[!] scan: could not create %s, skipping %s: %v\n", pathForDomain, opts.Domain, err)
		return
	}

	ctx := opts.context()
	ctx.Domain = fullDomain
	ctx.ScanPath = pathForDomain

	core.RunModules(ctx, opts.webModules())
}
