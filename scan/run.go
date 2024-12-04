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

	/*
	   - naabu
	   - katana
	   - wappalyzergo
	   - sitemap
	   - robots.txt
	   - gobuster
	   - nuclei
	   - httpx
	   - gowitness
	*/

}
