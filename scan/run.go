package scan

import (
	"evil.djnn.sh/djnn/yellow/helpers"
	"fmt"
	"os"
)

type ScanOpts struct {
	domain        string
	scanPath      string
	proxy         string
	dryRun        bool
	rateLimit     int32
	wordlistPath  string
	forceInsecure bool
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

func (opts ScanOpts) runRobots(scanFile string) {

	rb := Sitemap{}
	rbCfg := make(map[string]interface{})

	rbCfg["ScanPath"] = scanFile
	rbCfg["Proxy"] = opts.proxy

	rb.Configure(rbCfg)
	rb.Info(opts.domain)
	if !opts.dryRun {
		rb.Run(opts.domain)
	}
}

func (opts ScanOpts) runSitemap(scanFile string) {

	sm := Sitemap{}
	smCfg := make(map[string]interface{})

	smCfg["ScanPath"] = scanFile
	smCfg["Proxy"] = opts.proxy

	sm.Configure(smCfg)
	sm.Info(opts.domain)
	if !opts.dryRun {
		sm.Run(opts.domain)
	}
}

func (opts ScanOpts) runNaabu(scanFile string) {

	nb := Naabu{}
	nbCfg := make(map[string]interface{})

	nbCfg["ScanPath"] = scanFile
	nbCfg["Proxy"] = opts.proxy
	nbCfg["RateLimit"] = opts.rateLimit

	nb.Configure(nbCfg)
	nb.Info(opts.domain)
	if !opts.dryRun {
		nb.Run(opts.domain)
	}
}

func (opts *ScanOpts) Run() {
	fmt.Printf("\n[SCAN] domain: %s\n\n", opts.domain)

	/* make a directory with the domain name to organize results a bit */
	fullPath := opts.scanPath + "/" + opts.domain
	if !helper.Exists(fullPath) {
		err := os.MkdirAll(fullPath, 0775)
		if err != nil {
			panic(err)
		}
	}

	naabuScanFile := fullPath + "/open-ports-top-1000.txt"
	opts.SetScanPath(naabuScanFile)

	opts.runNaabu(opts.domain)
	opts.runSitemap(opts.domain)
	opts.runRobots(opts.domain)

	/*
	   - gobuster
	   - wappalyzergo
	   - katana
	   - nuclei
	   - httpx
	   - gowitness
	*/

}
