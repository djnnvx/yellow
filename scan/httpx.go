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

func (h *Httpx) Configure(c interface{}) {
	h.OutDirPath = c.(map[string]interface{})["OutDirPath"].(string)
	h.Proxy = c.(map[string]interface{})["Proxy"].(string)
	h.RateLimit = c.(map[string]interface{})["RateLimit"].(int32)
	h.Insecure = c.(map[string]interface{})["Insecure"].(bool)
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
		panic(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		panic(err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
	fmt.Printf("[SCAN %s] httpx completed.\n\n", domain)
}
