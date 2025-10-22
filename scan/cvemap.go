package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/cvemap/pkg/runner"
	"github.com/projectdiscovery/cvemap/pkg/types"
)

type Cvemap struct {
	HTTPProxy string
	scanPath  string
	Limit     int
	Offset    int
	Verbose   bool
	Debug     bool
}

func (c *Cvemap) Info(target string) {
	fmt.Println("[+] Running cvemap for", target)
}

func (c *Cvemap) Configure(cfg any) {
	if cfg == nil {
		return
	}
	m := cfg.(map[string]any)

	if v, ok := m["Proxy"].(string); ok {
		c.HTTPProxy = v
	}
	if v, ok := m["Limit"].(int); ok {
		c.Limit = v
	}
	if v, ok := m["Offset"].(int); ok {
		c.Offset = v
	}
	if v, ok := m["Verbose"].(bool); ok {
		c.Verbose = v
	}
	if v, ok := m["Debug"].(bool); ok {
		c.Debug = v
	}
	if v, ok := m["ScanPath"].(string); ok {
		c.scanPath = v
	}
}

func (c *Cvemap) Run(techs []string) {
	runner.PDCPApiKey = os.Getenv("VULNX_API_KEY")
	if runner.PDCPApiKey == "" {
		println("[!] Automatic CVE research requires VULNX_API_KEY to be set in env...skipping")
		return
	}

	options := runner.Options{
		HTTPProxy: c.HTTPProxy,
		Limit:     c.Limit,
		Offset:    c.Offset,
		Verbose:   c.Verbose,
		Debug:     c.Debug,
	}

	rn, err := runner.New(&options)
	if err != nil {
		panic(err)
	}

	if len(techs) == 0 {
		fmt.Println("[+] no technologies provided")
		return
	}

	for _, tech := range techs {
		tech = strings.TrimSpace(tech)
		if tech == "" {
			continue
		}

		c.Info(tech)

		rn.Options.Search = tech

		cvesResp, err := rn.GetCves()
		if err != nil {
			fmt.Printf("[ERROR] query for '%s' failed: %v\n", tech, err)
			continue
		}
		if cvesResp == nil {
			fmt.Printf("[SCAN %s] no results\n\n", tech)
			continue
		}

		total := 0
		if cvesResp.TotalResults > 0 {
			total = cvesResp.TotalResults
		} else if cvesResp.Cves != nil {
			total = len(cvesResp.Cves)
		}

		c.saveResults(cvesResp.Cves)
		fmt.Printf("[SCAN %s] total results: %d (returned: %d)\n\n", tech, total, len(cvesResp.Cves))
	}
}

func (c *Cvemap) saveResults(names []types.CVEData) {
	data, err := json.MarshalIndent(names, "", "\t")
	if err != nil {
		return
	}

	filename := c.scanPath + "/cves.json"
	if err := os.WriteFile(filename, data, 0644); err != nil {
		panic(err)
	}
}
