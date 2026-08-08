package scan

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"evil.djnn.sh/djnn/yellow/core"
	helper "evil.djnn.sh/djnn/yellow/helpers"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/katana/pkg/engine/hybrid"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils/scope"
)

const katanaFieldScope = "rdn"

type Katana struct {
	Depth    int
	Duration time.Duration
}

func (*Katana) Name() string { return "katana" }

func (k *Katana) Run(ctx *core.Context) error {
	fmt.Println("[+] Running katana on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	chrome := helper.SystemChromePath()
	if chrome == "" {
		fmt.Println("[+] katana: no system chrome found, headless engine will download one on first run")
	}

	// katana outputs URLs found past MaxDepth without checking scope
	// (engine/common/base.go), so third-party hosts reach OnResult and end up in
	// ctx.URLs, where nuclei/gobuster/secrets would scan them. Re-apply katana's
	// own check on the way out.
	target, err := url.Parse(ctx.Domain)
	if err != nil {
		fmt.Printf("[!] katana: invalid target %s: %v\n", ctx.Domain, err)
		return nil
	}
	scoper, err := scope.NewManager(nil, nil, katanaFieldScope, false)
	if err != nil {
		fmt.Printf("[!] katana: could not build scope manager: %v\n", err)
		return nil
	}

	var (
		mu      sync.Mutex
		seen    = map[string]bool{}
		urls    []string
		dropped int
	)

	options := &types.Options{
		MaxDepth:           k.Depth,
		CrawlDuration:      k.Duration,
		FieldScope:         katanaFieldScope,
		BodyReadSize:       math.MaxInt,
		Timeout:            10,
		TimeStable:         1, // 0 makes rod's WaitDOMStable panic on NewTicker(0)
		DOMWaitTime:        5,
		Concurrency:        10,
		Parallelism:        10,
		Strategy:           "depth-first",
		RateLimit:          int(ctx.RateLimit),
		Proxy:              ctx.Proxy,
		Headless:           true,
		HeadlessHybrid:     true,
		HeadlessNoSandbox:  os.Geteuid() == 0,
		UseInstalledChrome: chrome != "",
		SystemChromePath:   chrome,
		XhrExtraction:      true,
		DisableUpdateCheck: true,
		NoColors:           true, // Silent would mute gologger globally, hiding later modules' warnings
		CustomHeaders:      goflags.StringSlice{"User-Agent: " + helper.GetUserAgent()},
		OnResult: func(result output.Result) {
			if result.Request == nil || result.Request.URL == "" {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[result.Request.URL] {
				return
			}
			seen[result.Request.URL] = true

			if !inScope(scoper, result.Request.URL, target.Hostname()) {
				dropped++
				return
			}
			urls = append(urls, result.Request.URL)
		},
	}
	if options.RateLimit <= 0 {
		options.RateLimit = 150
	}

	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		fmt.Printf("[!] katana: could not build crawler options: %v\n", err)
		return nil
	}
	defer crawlerOptions.Close()

	crawler, err := hybrid.New(crawlerOptions)
	if err != nil {
		fmt.Printf("[!] katana: could not start headless crawler, skipping: %v\n", err)
		return nil
	}
	defer crawler.Close()

	if err := crawler.Crawl(ctx.Domain); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
			fmt.Printf("[+] katana: hit the %s crawl budget, keeping what was found\n", k.Duration)
		} else {
			fmt.Printf("[!] katana: crawl failed for %s: %v\n", ctx.Domain, err)
		}
	}

	mu.Lock()
	sort.Strings(urls)
	mu.Unlock()

	outfile := fmt.Sprintf("%s/katana.txt", ctx.ScanPath)
	if err := core.WriteLines(outfile, urls); err != nil {
		fmt.Printf("[!] katana: could not write %s: %v\n", outfile, err)
	}

	ctx.URLs = urls
	if dropped > 0 {
		fmt.Printf("[+] katana: dropped %d out-of-scope URL(s)\n", dropped)
	}
	fmt.Printf("[SCAN %s] katana crawled %d URL(s) in %s\n\n", ctx.Domain, len(urls), outfile)
	return nil
}

func inScope(scoper *scope.Manager, rawURL, rootHostname string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	ok, err := scoper.Validate(u, rootHostname)
	return err == nil && ok
}
