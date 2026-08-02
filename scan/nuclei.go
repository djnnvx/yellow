package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"evil.djnn.sh/djnn/yellow/core"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type nucleiFinding struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Matched    string `json:"matched,omitempty"`
}

type Nuclei struct {
	MaxURLs int
}

func (*Nuclei) Name() string { return "nuclei" }

func (n *Nuclei) Run(ctx *core.Context) error {
	fmt.Println("[+] Running nuclei on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	// Install the template repo up front. On a fresh machine nuclei pulls
	// hundreds of MB; doing it here (instead of lazily mid-scan) keeps the
	// download visible and lets us skip nuclei cleanly if it fails, without
	// stalling or half-breaking the rest of the scan. No-op once installed.
	fmt.Println("[+] nuclei: ensuring templates are installed (first run downloads them, this can take a while)...")
	tm := installer.TemplateManager{}
	if err := tm.FreshInstallIfNotExists(); err != nil {
		fmt.Printf("[!] nuclei: templates unavailable, skipping: %v\n", err)
		return nil
	}

	engine, err := nuclei.NewNucleiEngineCtx(
		context.Background(),
		// skip info/unknown noise; focus on actionable findings
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity: "low,medium,high,critical",
		}),
		// templates are managed above; don't let the engine auto-upgrade over the network
		nuclei.WithTemplateUpdateCallback(true, func(string) {}),
	)
	if err != nil {
		fmt.Printf("[!] nuclei: could not start engine: %v\n", err)
		return nil
	}
	defer engine.Close()

	targets := capURLs(ctx.URLs, n.MaxURLs, "nuclei")
	if len(targets) == 0 {
		targets = []string{ctx.Domain}
	}
	fmt.Printf("[+] nuclei: loading %d target(s)\n", len(targets))
	engine.LoadTargets(targets, false)

	// nuclei invokes the callback from concurrent template workers, so the
	// shared findings slice needs a lock.
	var (
		mu       sync.Mutex
		findings = []nucleiFinding{}
	)
	err = engine.ExecuteCallbackWithCtx(context.Background(), func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		f := nucleiFinding{
			TemplateID: event.TemplateID,
			Name:       event.Info.Name,
			Severity:   event.Info.SeverityHolder.Severity.String(),
			Matched:    event.Matched,
		}
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
		fmt.Printf("[SCAN %s] nuclei: [%s] %s (%s)\n", ctx.Domain, f.Severity, f.Name, f.Matched)
	})
	if err != nil {
		fmt.Printf("[!] nuclei: execution failed: %v\n", err)
		return nil
	}

	outfile := fmt.Sprintf("%s/nuclei.json", ctx.ScanPath)
	data, _ := json.MarshalIndent(findings, "", "\t")
	if err := os.WriteFile(outfile, data, 0644); err != nil {
		fmt.Printf("[!] nuclei: could not write %s: %v\n", outfile, err)
	}

	fmt.Printf("[SCAN %s] nuclei scan completed, %d finding(s) in %s\n\n", ctx.Domain, len(findings), outfile)
	return nil
}
