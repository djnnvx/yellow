package scan

import (
	"evil.djnn.sh/djnn/yellow/helpers"
	"fmt"
)

type ScanOpts struct {
	domain        string
	scanPath      string
	proxy         string
	dryRun        bool
	rateLimit     int32
	wordlistPath  string
	forceInsecure bool
	withPortScan  bool
}

func (opts *ScanOpts) SetWithPortScan(data bool) {
	opts.withPortScan = data
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

func (opts ScanOpts) runRobots() {

	rb := Sitemap{}
	rbCfg := make(map[string]any)

	rbCfg["Proxy"] = opts.proxy

	rb.Configure(rbCfg)
	rb.Info(opts.domain)
	if !opts.dryRun {
		rb.Run(opts.domain)
	}
}

func (opts ScanOpts) runWappalyzerGo() {

	wp := WappalyzerGo{}
	wpCfg := make(map[string]any)

	wpCfg["Proxy"] = opts.proxy

	wp.Configure(wpCfg)
	wp.Info(opts.domain)
	if !opts.dryRun {
		wp.Run(opts.domain)
	}
}

func (opts ScanOpts) runSitemap() {

	sm := Sitemap{}
	smCfg := make(map[string]any)

	smCfg["Proxy"] = opts.proxy

	sm.Configure(smCfg)
	sm.Info(opts.domain)
	if !opts.dryRun {
		sm.Run(opts.domain)
	}
}

func (opts ScanOpts) runNaabu() {

	nb := Naabu{}
	nbCfg := make(map[string]any)

	nbCfg["ScanPath"] = opts.scanPath
	nbCfg["Proxy"] = opts.proxy
	nbCfg["RateLimit"] = opts.rateLimit

	nb.Configure(nbCfg)
	nb.Info(opts.domain)
	if !opts.dryRun {
		nb.Run(opts.domain)
	}
}

func (opts *ScanOpts) runHttpx() {
	httpx := Httpx{}
	httpxCfg := make(map[string]any)

	httpxOutdir := fmt.Sprintf("%s/httpx", opts.scanPath)

	httpxCfg["OutDirPath"] = httpxOutdir
	httpxCfg["Proxy"] = opts.proxy
	httpxCfg["RateLimit"] = opts.rateLimit
	httpxCfg["Insecure"] = opts.forceInsecure

	httpx.Configure(httpxCfg)
	httpx.Info(opts.domain)

	if !opts.dryRun {
		httpx.Run(opts.domain)
	}
}

func (opts ScanOpts) runGobusterDir() {

	nb := Gobuster{}
	nbCfg := make(map[string]any)

	nbCfg["scanPath"] = opts.scanPath
	nbCfg["proxy"] = opts.proxy
	nbCfg["rateLimit"] = opts.rateLimit
	nbCfg["wordlist"] = opts.wordlistPath
	nbCfg["insecure"] = opts.forceInsecure

	nb.Configure(nbCfg)
	nb.Info(opts.domain)
	if !opts.dryRun {
		nb.Run(opts.domain)
	}
}

func (opts *ScanOpts) Run() {
	fmt.Printf("\n[SCAN] domain: %s\n", opts.domain)

	if opts.withPortScan {
		oldScan := opts.scanPath
		naabuScanFile := oldScan + "/" + opts.domain + "_open-ports-top-1000.txt"
		opts.SetScanPath(naabuScanFile)

		opts.runNaabu()
		opts.SetScanPath(oldScan)
	}

	if opts.forceInsecure {
		opts.SetDomain("http://" + opts.domain)
	} else {
		opts.SetDomain("https://" + opts.domain)
	}

	if !helper.HasUnavailableWebInterface(opts.domain) {

		fmt.Printf("[SCAN %s] web panel online....running web scans\n", opts.domain)

		opts.runSitemap()
		opts.runRobots()
		opts.runWappalyzerGo()
		opts.runHttpx()
		opts.runGobusterDir()

	} else {
		fmt.Printf("[SCAN %s] => no web panel online. skipping\n", opts.domain)
	}
}
