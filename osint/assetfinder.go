package osint

import (
	"fmt"
	"os"
	"sync"
	"time"

	"evil.djnn.sh/djnn/yellow/core"
	// old fork that dissociates main from runner
	// (repo was deleted but module still exists, and the tool has not
	// been updated in 4 years so...)
	assetfinder "github.com/spiral-sec/assetfinder/scanner"
)

type fetchFn func(string) ([]string, error)

type Assetfinder struct{}

func (*Assetfinder) Name() string { return "assetfinder" }

func (*Assetfinder) Run(ctx *core.Context) error {
	fmt.Println("[+] Running Assetfinder on ", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	outfile := fmt.Sprintf("%s/assetfinder.txt", ctx.ScanPath)
	functions := []fetchFn{
		assetfinder.CertSpotter,
		assetfinder.HackerTarget,
		assetfinder.ThreatCrowd,
		assetfinder.CrtSh,
		assetfinder.Facebook,
		assetfinder.VirusTotal,
		assetfinder.FindSubDomains,
		assetfinder.Urlscan,
		assetfinder.BufferOverrun,
	}

	var wg sync.WaitGroup
	rl := assetfinder.NewRateLimiter(time.Second)
	out := make(chan string)

	for _, f := range functions {
		wg.Add(1)
		fn := f

		go func() {
			defer wg.Done()

			rl.Block(fmt.Sprintf("%#v", fn))
			names, err := fn(ctx.Domain)

			if err != nil {
				return
			}

			for _, n := range names {
				n = assetfinder.CleanDomain(n)
				out <- n
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	printed := make(map[string]bool)
	file, err := os.OpenFile(outfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil
	}
	defer file.Close()

	for n := range out {
		if _, ok := printed[n]; ok {
			continue
		}
		printed[n] = true
		fmt.Println(n)
		file.WriteString(n + "\n")
	}

	fmt.Printf("[OSINT %s] Assetfinder done.\n\n", ctx.Domain)
	return nil
}
