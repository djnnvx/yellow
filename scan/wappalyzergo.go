package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"sort"

	"evil.djnn.sh/djnn/yellow/core"
	helper "evil.djnn.sh/djnn/yellow/helpers"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type WappalyzerGo struct{}

func (*WappalyzerGo) Name() string { return "wappalyzergo" }

func (d *WappalyzerGo) Run(ctx *core.Context) error {
	fmt.Println("[+] Running WappalyzerGo on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	targetURL := ctx.Domain
	client := d.newHTTPClient()

	resp, body, err := d.fetchResponse(client, targetURL)
	if err != nil {
		fmt.Printf("error fetching %s: %v\n", targetURL, err)
		fmt.Printf("[SCAN %s] WappalyzerGo scan for %s completed\n\n", targetURL, targetURL)
		return nil
	}
	if resp != nil {
		defer resp.Body.Close()
	}

	results, err := d.fingerprint(resp, body)
	if err != nil {
		fmt.Printf("error fingerprinting %s: %v\n", targetURL, err)
		fmt.Printf("[SCAN %s] WappalyzerGo scan for %s completed\n\n", targetURL, targetURL)
		return nil
	}

	names := techNamesFromResults(results)
	filename, err := d.saveNames(names, ctx.ScanPath)
	if err != nil {
		fmt.Printf("error saving results for %s: %v\n", targetURL, err)
	} else {
		fmt.Printf("[SCAN %s] WappalyzerGo results are stored in %s\n", targetURL, filename)
	}

	fmt.Printf("%v\n", names)
	fmt.Printf("[SCAN %s] WappalyzerGo scan for %s completed\n\n", targetURL, targetURL)

	ctx.Techs = names
	return nil
}

func (d *WappalyzerGo) newHTTPClient() *http.Client {
	return helper.GetHttpClient(true)
}

func (d *WappalyzerGo) fetchResponse(client *http.Client, targetURL string) (*http.Response, []byte, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Add("User-Agent", helper.GetUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return resp, nil, fmt.Errorf("performing request: %w", err)
	}

	if resp == nil {
		return nil, nil, fmt.Errorf("no response received")
	}

	body, _, err := helper.ReadCappedBody(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("reading response body: %w", err)
	}

	return resp, body, nil
}

func (d *WappalyzerGo) fingerprint(resp *http.Response, body []byte) (any, error) {
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		return nil, fmt.Errorf("initializing wappalyzer client: %w", err)
	}

	results := wappalyzerClient.Fingerprint(resp.Header, body)
	return results, nil
}

func (d *WappalyzerGo) saveNames(names []string, scanPath string) (string, error) {
	data, err := json.MarshalIndent(names, "", "\t")
	if err != nil {
		return "", fmt.Errorf("marshal names: %w", err)
	}

	filename := scanPath + "/wappalyzer.json"
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", fmt.Errorf("write file %s: %w", filename, err)
	}

	return filename, nil
}

func techNamesFromResults(results any) []string {
	if s, ok := results.([]string); ok {
		out := make([]string, len(s))
		copy(out, s)
		sort.Strings(out)
		return out
	}

	if si, ok := results.([]interface{}); ok {
		out := make([]string, 0, len(si))
		for _, v := range si {
			out = append(out, fmt.Sprint(v))
		}
		sort.Strings(out)
		return out
	}

	val := reflect.ValueOf(results)
	if val.Kind() == reflect.Map {
		out := make([]string, 0, val.Len())
		for _, k := range val.MapKeys() {
			out = append(out, fmt.Sprint(k.Interface()))
		}
		sort.Strings(out)
		return out
	}

	return []string{fmt.Sprint(results)}
}
