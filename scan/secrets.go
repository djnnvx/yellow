package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"evil.djnn.sh/djnn/yellow/core"
	helper "evil.djnn.sh/djnn/yellow/helpers"
	"github.com/zricethezav/gitleaks/v8/detect"
)

const maxSecretBodySize = 10 << 20

type SecretFinding struct {
	URL         string  `json:"url"`
	RuleID      string  `json:"rule_id"`
	Description string  `json:"description"`
	Secret      string  `json:"secret"`
	Match       string  `json:"match"`
	Line        int     `json:"line"`
	Entropy     float32 `json:"entropy"`
	Fingerprint string  `json:"fingerprint"`
}

type Secrets struct {
	MaxURLs int
}

var (
	detectorOnce sync.Once
	detector     *detect.Detector
)

func secretDetector() *detect.Detector {
	detectorOnce.Do(func() {
		d, err := detect.NewDetectorDefaultConfig()
		if err != nil {
			fmt.Printf("[!] secrets: could not load gitleaks rules: %v\n", err)
			return
		}
		detector = d
	})
	return detector
}

var scannableTypes = []string{
	"javascript", "json", "html", "css", "xml", "text/plain", "ecmascript",
}

func shouldScanBody(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, t := range scannableTypes {
		if strings.Contains(ct, t) {
			return true
		}
	}
	return false
}

func (*Secrets) Name() string { return "secrets" }

func (s *Secrets) Run(ctx *core.Context) error {
	fmt.Println("[+] Running secrets scan on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	d := secretDetector()
	if d == nil {
		return nil
	}

	targets := capURLs(ctx.URLs, s.MaxURLs, "secrets")
	if len(targets) == 0 {
		targets = []string{ctx.Domain}
	}

	client := helper.GetHttpClient(true)

	var (
		mu       sync.Mutex
		seen     = map[string]bool{}
		findings = []SecretFinding{}
		scanned  int
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, 10)

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()

			body, ok := fetchScannable(client, url)
			if !ok {
				return
			}

			mu.Lock()
			scanned++
			mu.Unlock()

			for _, f := range d.DetectBytes(body) {
				rec := SecretFinding{
					URL:         url,
					RuleID:      f.RuleID,
					Description: f.Description,
					Secret:      f.Secret,
					Match:       strings.TrimSpace(f.Match),
					Line:        f.StartLine,
					Entropy:     f.Entropy,
					Fingerprint: f.Fingerprint,
				}
				key := rec.Fingerprint
				if key == "" {
					key = rec.RuleID + ":" + rec.Secret
				}

				mu.Lock()
				if !seen[key] {
					seen[key] = true
					findings = append(findings, rec)
					fmt.Printf("[SCAN %s] secrets: [%s] %s in %s\n", ctx.Domain, rec.RuleID, rec.Description, url)
				}
				mu.Unlock()
			}
		}(target)
	}
	wg.Wait()

	outfile := fmt.Sprintf("%s/secrets.json", ctx.ScanPath)
	data, _ := json.MarshalIndent(findings, "", "\t")
	if err := os.WriteFile(outfile, data, 0644); err != nil {
		fmt.Printf("[!] secrets: could not write %s: %v\n", outfile, err)
	}

	fmt.Printf("[SCAN %s] secrets: %d finding(s) across %d URL(s) in %s\n\n",
		ctx.Domain, len(findings), scanned, outfile)
	return nil
}

func fetchScannable(client *http.Client, url string) ([]byte, bool) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", helper.GetUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	if !shouldScanBody(resp.Header.Get("Content-Type")) {
		return nil, false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSecretBodySize))
	if err != nil {
		return nil, false
	}
	return body, true
}
