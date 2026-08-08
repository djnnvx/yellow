package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"sync"
	"sync/atomic"

	"evil.djnn.sh/djnn/yellow/core"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type nucleiFinding struct {
	TemplateID string   `json:"template_id"`
	Name       string   `json:"name,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Host       string   `json:"host,omitempty"`
	Matched    []string `json:"matched,omitempty"`
}

type Nuclei struct {
	MaxURLs int
}

// matchLocation reports where a finding hit. nuclei leaves Matched empty on some
// events, which loses the only pointer to the target; its own screen writer
// falls back to Host, and URL is more precise than that.
func matchLocation(event *output.ResultEvent) string {
	for _, s := range []string{event.Matched, event.URL, event.Host} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// findingSet groups hits by template and host. One template matching 300 crawled
// URLs on the same host is one finding with 300 locations, not 300 findings.
// It owns its lock because nuclei calls back from concurrent template workers.
type findingSet struct {
	mu sync.Mutex
	by map[string]*nucleiFinding
}

func newFindingSet() *findingSet {
	return &findingSet{by: map[string]*nucleiFinding{}}
}

// add records a hit and reports whether it opened a new group. It returns a nil
// finding for anything that is not a real match: nuclei routes failed matchers
// and skipped hosts through the same callback (WriteFailure -> Write), and those
// carry MatcherStatus false with no Matched. Counting them as findings turns one
// rate-limited host into a "finding" per template.
func (s *findingSet) add(event *output.ResultEvent) (*nucleiFinding, bool) {
	if event == nil || !event.MatcherStatus {
		return nil, false
	}

	loc := matchLocation(event)
	host := loc
	if u, err := url.Parse(loc); err == nil && u.Host != "" {
		host = u.Host
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := event.TemplateID + " " + host
	f, seen := s.by[key]
	if !seen {
		f = &nucleiFinding{
			TemplateID: event.TemplateID,
			Name:       event.Info.Name,
			Severity:   event.Info.SeverityHolder.Severity.String(),
			Host:       host,
		}
		s.by[key] = f
	}
	f.Matched = append(f.Matched, loc)
	return f, !seen
}

// sorted returns the groups in a stable order, noisiest first.
func (s *findingSet) sorted() []nucleiFinding {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]nucleiFinding, 0, len(s.by))
	for _, f := range s.by {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Matched) != len(out[j].Matched) {
			return len(out[i].Matched) > len(out[j].Matched)
		}
		if out[i].TemplateID != out[j].TemplateID {
			return out[i].TemplateID < out[j].TemplateID
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func (s *findingSet) hits() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := 0
	for _, f := range s.by {
		total += len(f.Matched)
	}
	return total
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

	targets := capURLs(collapseCatchAll(ctx.URLs, answersEveryPath), n.MaxURLs, "nuclei")
	if len(targets) == 0 {
		targets = []string{ctx.Domain}
	}
	fmt.Printf("[+] nuclei: loading %d target(s)\n", len(targets))
	engine.LoadTargets(targets, false)

	findings := newFindingSet()
	var nonMatches atomic.Int64
	err = engine.ExecuteCallbackWithCtx(context.Background(), func(event *output.ResultEvent) {
		f, isNew := findings.add(event)
		if f == nil {
			nonMatches.Add(1)
			return
		}
		// only announce the first hit of each group; the rest land in nuclei.json
		if isNew {
			fmt.Printf("[SCAN %s] nuclei: [%s] %s on %s\n", ctx.Domain, f.Severity, f.Name, f.Host)
		}
	})
	if err != nil {
		fmt.Printf("[!] nuclei: execution failed: %v\n", err)
		return nil
	}

	if n := nonMatches.Load(); n > 0 {
		fmt.Printf("[+] nuclei: ignored %d non-match event(s) (failed matchers, unresponsive hosts)\n", n)
	}

	grouped := findings.sorted()
	outfile := fmt.Sprintf("%s/nuclei.json", ctx.ScanPath)
	data, _ := json.MarshalIndent(grouped, "", "\t")
	if err := os.WriteFile(outfile, data, 0644); err != nil {
		fmt.Printf("[!] nuclei: could not write %s: %v\n", outfile, err)
	}

	fmt.Printf("[SCAN %s] nuclei scan completed, %d finding(s) from %d hit(s) in %s\n\n",
		ctx.Domain, len(grouped), findings.hits(), outfile)
	return nil
}
