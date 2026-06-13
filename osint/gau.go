package osint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"evil.djnn.sh/djnn/yellow/core"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/lc/gau/v2/runner"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

type Gau struct{}

func (*Gau) Name() string { return "gau" }

func (*Gau) Run(ctx *core.Context) error {
	fmt.Println("[+] Running gau on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	domain := gauDomain(ctx.Domain)

	client := &fasthttp.Client{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		TLSConfig:    &tls.Config{InsecureSkipVerify: true},
	}
	if ctx.Proxy != "" {
		host := strings.TrimPrefix(strings.TrimPrefix(ctx.Proxy, "http://"), "https://")
		client.Dial = fasthttpproxy.FasthttpHTTPDialer(host)
	}

	config := &providers.Config{
		Threads:           3,
		Timeout:           45,
		MaxRetries:        2,
		IncludeSubdomains: true,
		Client:            client,
		Providers:         []string{"wayback", "commoncrawl", "otx", "urlscan"},
		Blacklist:         mapset.NewSet[string](),
		// URLScan.Host left empty so gau uses its built-in default base URL
	}

	gau := &runner.Runner{}
	if err := gau.Init(config, config.Providers, providers.Filters{}); err != nil {
		fmt.Printf("[!] gau: could not init: %v\n", err)
		return nil
	}

	results := make(chan string)
	seen := map[string]struct{}{}
	var urls []string
	done := make(chan struct{})
	go func() {
		for u := range results {
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			urls = append(urls, u)
		}
		close(done)
	}()

	rctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// buffered + filled before Start so a cancelled rctx can't deadlock the sends
	workChan := make(chan runner.Work, len(gau.Providers))
	for _, p := range gau.Providers {
		workChan <- runner.NewWork(domain, p)
	}
	close(workChan)
	gau.Start(rctx, workChan, results)
	gau.Wait()
	close(results)
	<-done

	outfile := fmt.Sprintf("%s/urls.txt", ctx.ScanPath)
	content := strings.Join(urls, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(outfile, []byte(content), 0644); err != nil {
		fmt.Printf("[!] gau: could not write %s: %v\n", outfile, err)
		return nil
	}

	fmt.Printf("[OSINT %s] gau collected %d historical URL(s) in %s\n", domain, len(urls), outfile)
	return nil
}

func gauDomain(target string) string {
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return strings.TrimSpace(target)
}
