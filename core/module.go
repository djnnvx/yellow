package core

import "fmt"

// Context carries config and shared state for a single target through every Module.
type Context struct {
	Domain    string // current target (full URL for scan, domain for osint)
	ScanPath  string // per-target output directory
	Proxy     string
	DryRun    bool
	RateLimit int32

	Wordlist   string // scan: gobuster wordlist
	Insecure   bool   // scan: skip TLS verification / force http
	EmailsFile string // osint: leaker emails file

	Techs   []string // scan: wappalyzer detections, consumed by cvemap
	Domains []string // osint: discovered assets, consumed by shodan
}

// Module is a single recon step. Run reports its own progress to stdout and
// returns an error only for failures the orchestrator should surface.
type Module interface {
	Name() string
	Run(ctx *Context) error
}

// RunModules runs each module in order, surfacing any error it returns.
func RunModules(ctx *Context, modules []Module) {
	for _, m := range modules {
		if err := m.Run(ctx); err != nil {
			fmt.Printf("[!] %s: %v\n", m.Name(), err)
		}
	}
}
