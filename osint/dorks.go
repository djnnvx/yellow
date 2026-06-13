package osint

import (
	"fmt"

	"evil.djnn.sh/djnn/yellow/core"
	dorks "github.com/bogdzn/gork/cmd"
)

type Dorks struct{}

func (*Dorks) Name() string { return "dorks" }

func (*Dorks) Run(ctx *core.Context) error {
	fmt.Println("[+] Running dorks on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	outfile := fmt.Sprintf("%s/dorks.txt", ctx.ScanPath)
	opts := &dorks.Options{
		Proxy:         ctx.Proxy,
		Outfile:       outfile,
		AppendResults: false,
		Extensions:    dorks.DefaultFileExtensions(),
		Exclusions:    dorks.DefaultExclusions(),
		UserAgent:     dorks.DefaultUserAgent(),
		Target:        ctx.Domain,
	}

	dorks.Run(opts)
	fmt.Printf("[OSINT %s] Dorks are stored in %s\n\n", ctx.Domain, outfile)
	return nil
}
