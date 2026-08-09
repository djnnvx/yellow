package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"evil.djnn.sh/djnn/yellow/core"
	helper "evil.djnn.sh/djnn/yellow/helpers"
)

// NVD rate limits: 5 req/30s without key, 50 req/30s with key.
// We sleep conservatively between queries to avoid 403s.
const (
	nvdDelayNoKey   = 7 * time.Second
	nvdDelayWithKey = 1 * time.Second
)

const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type Cvemap struct {
	HTTPProxy string
	scanPath  string
	Limit     int
	Offset    int
}

type nvdResponse struct {
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string     `json:"id"`
	Published    string     `json:"published"`
	LastModified string     `json:"lastModified"`
	Descriptions []nvdDesc  `json:"descriptions"`
	Metrics      nvdMetrics `json:"metrics"`
	Weaknesses   []nvdWeak  `json:"weaknesses"`
	References   []nvdRef   `json:"references"`
}

type nvdDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSv31 []nvdCVSS `json:"cvssMetricV31,omitempty"`
	CVSSv30 []nvdCVSS `json:"cvssMetricV30,omitempty"`
	CVSSv2  []nvdCVSS `json:"cvssMetricV2,omitempty"`
}

type nvdCVSS struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdWeak struct {
	Description []nvdDesc `json:"description"`
}

type nvdRef struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

func (*Cvemap) Name() string { return "cvemap" }

func (c *Cvemap) Run(ctx *core.Context) error {
	fmt.Println("[+] Running cvemap for", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	c.HTTPProxy = ctx.Proxy
	c.scanPath = ctx.ScanPath

	techs := ctx.Techs
	if len(techs) == 0 {
		fmt.Println("[+] no technologies provided")
		return nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if c.HTTPProxy != "" {
		proxyURL, err := url.Parse(c.HTTPProxy)
		if err != nil {
			fmt.Printf("[ERROR] invalid proxy URL: %v\n", err)
			return nil
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	apiKey := os.Getenv("NVD_API_KEY")
	delay := nvdDelayNoKey
	if apiKey != "" {
		delay = nvdDelayWithKey
	}

	limit := c.Limit
	if limit <= 0 {
		limit = 50
	}

	var allCVEs []nvdCVE

	queried := 0
	for _, tech := range techs {
		tech = strings.TrimSpace(tech)
		if tech == "" {
			continue
		}

		// wappalyzer formats versioned results as "TechName:version" — skip unversioned ones
		// since NVD results without a version are too noisy to be actionable
		colonIdx := strings.Index(tech, ":")
		if colonIdx == -1 {
			fmt.Printf("[+] skipping %s (no version detected)\n", tech)
			continue
		}
		name := tech[:colonIdx]
		version := tech[colonIdx+1:]
		query := name + " " + version

		if queried > 0 {
			time.Sleep(delay)
		}
		queried++

		fmt.Println("[+] Running cvemap for", query)

		cves, total, err := c.queryCVEs(client, apiKey, query, limit, c.Offset)
		if err != nil {
			fmt.Printf("[ERROR] query for '%s' failed: %v\n", tech, err)
			continue
		}

		fmt.Printf("[SCAN %s] total results: %d (returned: %d)\n\n", query, total, len(cves))
		allCVEs = append(allCVEs, cves...)
	}

	c.saveResults(allCVEs)
	return nil
}

func (c *Cvemap) queryCVEs(client *http.Client, apiKey, keyword string, limit, offset int) ([]nvdCVE, int, error) {
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", fmt.Sprintf("%d", limit))
	params.Set("startIndex", fmt.Sprintf("%d", offset))

	reqURL := fmt.Sprintf("%s?%s", nvdBaseURL, params.Encode())

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _, _ := helper.ReadCappedBody(resp.Body)
		return nil, 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, 0, err
	}

	cves := make([]nvdCVE, len(nvdResp.Vulnerabilities))
	for i, v := range nvdResp.Vulnerabilities {
		cves[i] = v.CVE
	}

	return cves, nvdResp.TotalResults, nil
}

func (c *Cvemap) saveResults(cves []nvdCVE) {
	data, err := json.MarshalIndent(cves, "", "\t")
	if err != nil {
		return
	}

	filename := c.scanPath + "/cves.json"
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("[!] cvemap: could not write %s: %v\n", filename, err)
	}
}
