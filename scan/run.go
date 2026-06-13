package scan

import (
	"fmt"
	"os"

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
	noGoBuster    bool
	portScan      bool
	ports         string
}

/*
save in shared memory to avoid having to read a write from files all the time
*/
var (
	wappalyzerResults []string
)

func (opts *ScanOpts) SetNoGobuster(data bool) {
	opts.noGoBuster = data
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

func (opts ScanOpts) runRobots() {

	rb := RobotsTxt{}
	rbCfg := make(map[string]any)

	rbCfg["Proxy"] = opts.proxy

	rb.Configure(rbCfg)
	rb.Info(opts.domain)
	if !opts.dryRun {
		rb.Run(opts.domain)
	}
}

func (opts ScanOpts) RunWappalyzerGo() {
	wappalyzerResults = make([]string, 0)

	wp := WappalyzerGo{}
	wpCfg := make(map[string]any)

	wpCfg["Proxy"] = opts.proxy
	wpCfg["ScanPath"] = opts.scanPath

	wp.Configure(wpCfg)
	wp.Info(opts.domain)
	if !opts.dryRun {
		wappalyzerResults = wp.Run(opts.domain)
	}
}

func (opts ScanOpts) RunCvemap() {
	cv := Cvemap{}
	cvCfg := make(map[string]any)

	cvCfg["Proxy"] = opts.proxy
	cvCfg["ScanPath"] = opts.scanPath
	cv.Configure(cvCfg)
	cv.Info(opts.domain)

	if !opts.dryRun {
		cv.Run(wappalyzerResults)
		wappalyzerResults = make([]string, 0)
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

	fullDomain := "https://" + opts.domain
	if opts.forceInsecure {
		fullDomain = "http://" + opts.domain
	}

	if opts.portScan {
		opts.runPortScan()
	}

	if !helper.HasUnavailableWebInterface(fullDomain) {

		fmt.Printf("[SCAN %s] web panel online....running web scans\n", opts.domain)

		pathForDomain := opts.scanPath + "/" + opts.domain
		err := os.MkdirAll(pathForDomain, 0755)
		if err != nil {
			panic(err)
		}

		/* modifying opts.scanPath directly would cause nested directories */
		runOpts := *opts
		runOpts.scanPath = pathForDomain
		runOpts.domain = fullDomain

		runOpts.runSitemap()
		runOpts.runRobots()
		runOpts.RunWappalyzerGo()
		runOpts.RunCvemap()
		runOpts.runHttpx()

		if !runOpts.noGoBuster {
			runOpts.runGobusterDir()
		}
	} else {
		fmt.Printf("[SCAN %s] => no web panel online. skipping\n", opts.domain)
	}
}
