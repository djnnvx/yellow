package scan

import (
	"fmt"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
)

type Httpx struct {
	Proxy      string
	OutDirPath string
	RateLimit  int32
	Insecure   bool
}

func (h *Httpx) Info(url string) {
	fmt.Println("[+] Running httpx on ", url)
}

func (h *Httpx) Configure(c any) {
	h.OutDirPath = c.(map[string]any)["OutDirPath"].(string)
	h.Proxy = c.(map[string]any)["Proxy"].(string)
	h.RateLimit = c.(map[string]any)["RateLimit"].(int32)
	h.Insecure = c.(map[string]any)["Insecure"].(bool)
}

func (h *Httpx) Run(domain string) {
	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           goflags.StringSlice{domain},
		HTTPProxy:                 h.Proxy,
		StoreResponseDir:          h.OutDirPath,
		Screenshot:                true,
		ScreenshotTimeout:         10 * time.Second,
		ScreenshotIdle:            1 * time.Second,
		RandomAgent:               true,
		UseInstalledChrome:        false,
		HeadlessOptionalArguments: nil,
		NoHeadlessBody:            false,
		RateLimit:                 int(h.RateLimit),
	}

	if err := options.ValidateOptions(); err != nil {
		fmt.Printf("[!] httpx: invalid options for %s: %v\n", domain, err)
		return
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		fmt.Printf("[!] httpx: could not create runner for %s: %v\n", domain, err)
		return
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
	fmt.Printf("[SCAN %s] httpx completed.\n\n", domain)
}
