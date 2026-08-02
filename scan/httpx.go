package scan

import (
	"fmt"
	"time"

	"evil.djnn.sh/djnn/yellow/core"
	helper "evil.djnn.sh/djnn/yellow/helpers"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
)

type Httpx struct{}

func (*Httpx) Name() string { return "httpx" }

func (*Httpx) Run(ctx *core.Context) error {
	fmt.Println("[+] Running httpx on ", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	domain := ctx.Domain
	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           goflags.StringSlice{domain},
		HTTPProxy:                 ctx.Proxy,
		StoreResponseDir:          fmt.Sprintf("%s/httpx", ctx.ScanPath),
		Screenshot:                true,
		ScreenshotTimeout:         10 * time.Second,
		ScreenshotIdle:            1 * time.Second,
		RandomAgent:               true,
		UseInstalledChrome:        helper.SystemChromePath() != "",
		HeadlessOptionalArguments: nil,
		NoHeadlessBody:            false,
		RateLimit:                 int(ctx.RateLimit),
	}

	if err := options.ValidateOptions(); err != nil {
		fmt.Printf("[!] httpx: invalid options for %s: %v\n", domain, err)
		return nil
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		fmt.Printf("[!] httpx: could not create runner for %s: %v\n", domain, err)
		return nil
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
	fmt.Printf("[SCAN %s] httpx completed.\n\n", domain)
	return nil
}
