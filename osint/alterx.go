package osint

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"evil.djnn.sh/djnn/yellow/core"
	"github.com/projectdiscovery/alterx"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

const (
	alterxLimit   = 5000
	alterxWorkers = 40
	alterxBudget  = 5 * time.Minute
)

type Alterx struct{}

func (*Alterx) Name() string { return "alterx" }

func (*Alterx) Run(ctx *core.Context) error {
	fmt.Println("[+] Running alterx on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	var inputs []string
	for _, d := range ctx.Domains {
		if d != "" && net.ParseIP(d) == nil {
			inputs = append(inputs, d)
		}
	}
	if len(inputs) == 0 {
		fmt.Println("[!] alterx: no subdomains to permute, skipping")
		return nil
	}

	mutator, err := alterx.New(&alterx.Options{Domains: inputs, Enrich: true})
	if err != nil {
		fmt.Printf("[!] alterx: %v\n", err)
		return nil
	}

	// Execute ignores Options.Limit; cap here, draining fully so the producer can't leak
	var candidates []string
	for c := range mutator.Execute(context.Background()) {
		if len(candidates) < alterxLimit {
			candidates = append(candidates, c)
		}
	}
	if len(candidates) == 0 {
		fmt.Println("[!] alterx: generated no candidates, skipping")
		return nil
	}

	live := resolveLive(candidates)

	existing := map[string]struct{}{}
	for _, d := range ctx.Domains {
		existing[d] = struct{}{}
	}
	var added []string
	for _, h := range live {
		if _, ok := existing[h]; ok {
			continue
		}
		existing[h] = struct{}{}
		added = append(added, h)
	}
	ctx.Domains = append(ctx.Domains, added...)

	outfile := fmt.Sprintf("%s/alterx.txt", ctx.ScanPath)
	if err := core.WriteLines(outfile, added); err != nil {
		fmt.Printf("[!] alterx: could not write %s: %v\n", outfile, err)
	}

	fmt.Printf("[OSINT %s] alterx: %d candidates, %d live, %d new in %s\n", ctx.Domain, len(candidates), len(live), len(added), outfile)
	return nil
}

func resolveLive(candidates []string) []string {
	opts := dnsx.DefaultOptions
	opts.MaxRetries = 2
	client, err := dnsx.New(opts)
	if err != nil {
		fmt.Printf("[!] alterx: dns resolver init failed: %v\n", err)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), alterxBudget)
	defer cancel()

	jobs := make(chan string)
	var (
		mu   sync.Mutex
		live []string
		wg   sync.WaitGroup
	)
	for i := 0; i < alterxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case name, ok := <-jobs:
					if !ok {
						return
					}
					if ips, err := client.Lookup(name); err == nil && len(ips) > 0 {
						mu.Lock()
						live = append(live, name)
						mu.Unlock()
					}
				}
			}
		}()
	}
dispatch:
	for _, c := range candidates {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- c:
		}
	}
	close(jobs)
	wg.Wait()
	return live
}
