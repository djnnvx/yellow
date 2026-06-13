package scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"evil.djnn.sh/djnn/yellow/core"
	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

type Tlsx struct{}

func (*Tlsx) Name() string { return "tlsx" }

func (*Tlsx) Run(ctx *core.Context) error {
	fmt.Println("[+] Running tlsx on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	host := tlsxHost(ctx.Domain)
	if host == "" {
		return nil
	}

	service, err := tlsx.New(&clients.Options{
		Timeout:    5,
		Retries:    1,
		ScanMode:   "auto",
		SAN:        true,
		TLSVersion: true,
	})
	if err != nil {
		fmt.Printf("[!] tlsx: %v\n", err)
		return nil
	}

	resp, err := service.Connect(host, "", "443")
	if err != nil || resp == nil {
		fmt.Printf("[!] tlsx: could not grab certificate for %s: %v\n", host, err)
		return nil
	}

	outfile := fmt.Sprintf("%s/tls.json", ctx.ScanPath)
	data, _ := json.MarshalIndent(resp, "", "\t")
	if err := os.WriteFile(outfile, data, 0644); err != nil {
		fmt.Printf("[!] tlsx: could not write %s: %v\n", outfile, err)
	}

	// certificate SANs frequently reveal extra hostnames worth chasing
	if resp.CertificateResponse != nil && len(resp.Domains) > 0 {
		fmt.Printf("[SCAN %s] tlsx: %d cert hostname(s): %s\n", host, len(resp.Domains), strings.Join(resp.Domains, ", "))
	}

	fmt.Printf("[SCAN %s] tlsx scan completed (TLS %s), results in %s\n\n", host, resp.Version, outfile)
	return nil
}

// tlsxHost extracts the bare hostname from a target that may be a full URL.
func tlsxHost(target string) string {
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return strings.TrimSpace(target)
}
