package osint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"evil.djnn.sh/djnn/yellow/helpers"
	"github.com/shadowscatcher/shodan"
	"github.com/shadowscatcher/shodan/search"
)

type Shodan struct {
	outfile string

	HTTPClient *http.Client
	apiKey     string
}

func (s Shodan) ShouldRun() bool {
	return s.apiKey != ""
}

func (s *Shodan) Info(target string) {
	if s.apiKey == "" {
		fmt.Println("[!] env value SHODAN_API_KEY not found. skipping shodan scan")
	} else {
		fmt.Println("[+] Running shodan on ", target)
	}
}

func (s *Shodan) Configure(c any) {
	s.apiKey = os.Getenv("SHODAN_API_KEY")

	s.outfile = c.(map[string]any)["outfile"].(string)
	if s.HTTPClient == nil {
		s.HTTPClient = &http.Client{
			Timeout: 15 * time.Second,
		}
	}
}

func (s *Shodan) Run(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		fmt.Println("err: empty ip provided")
		return
	}

	if net.ParseIP(ip) == nil {
		addrs, err := net.LookupHost(ip)
		if err != nil || len(addrs) == 0 {
			fmt.Printf("err: could not resolve %s to an IP: %v\n", ip, err)
			return
		}
		ip = addrs[0]
	}

	if s.apiKey == "" {
		fmt.Println("err: shodan api key not configured (set SHODAN_API_KEY or provide apikey in Configure)")
		return
	}

	if s.outfile == "" {
		fmt.Println("err: outfile not configured in Shodan (provide 'outfile' in Configure)")
		return
	}

	httpClient := s.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	client, err := shodan.GetClient(s.apiKey, httpClient, false)
	if err != nil {
		fmt.Printf("err: creating shodan client: %v\n", err)
		return
	}

	ctx := context.Background()
	hostParams := search.HostParams{
		IP: ip,
	}
	hostInfo, err := client.Host(ctx, hostParams)
	if err != nil {
		fmt.Printf("err: shodan host lookup failed for %s: %v\n", ip, err)
		return
	}

	rawJSON, err := json.Marshal(hostInfo)
	if err != nil {
		fmt.Printf("err: marshaling shodan response: %v\n", err)
		return
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, rawJSON, "", "\t"); err != nil {
		pretty.Write(rawJSON)
	}

	safeIP := strings.ReplaceAll(ip, ":", "-")
	outdir := filepath.Dir(s.outfile)
	if outdir == "." || outdir == "" {
		outdir = "."
	}
	jsonPath := filepath.Join(outdir, fmt.Sprintf("%s.shodan.json", safeIP))

	if err := os.WriteFile(jsonPath, pretty.Bytes(), 0o644); err != nil {
		fmt.Printf("warning: failed to write json file %s: %v\n", jsonPath, err)
	} else {
		fmt.Printf("wrote json: %s\n", jsonPath)
	}

	summary, perr := buildShodanSummaryFromJSON(bytes.NewReader(pretty.Bytes()), ip)
	if perr != nil {
		summary = fmt.Sprintf("IP: %s\n\n(Unable to build structured summary: %v)\n\n%s\n", ip, perr, string(pretty.Bytes()))
	}

	f, err := os.OpenFile(s.outfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Printf("err: unable to open outfile %s for append: %v\n", s.outfile, err)
		return
	}
	defer f.Close()

	sep := strings.Repeat("=", 80) + "\n"
	toWrite := fmt.Sprintf("%s\n%s\n\n", summary, sep)
	if _, err := f.WriteString(toWrite); err != nil {
		fmt.Printf("err: writing summary to %s: %v\n", s.outfile, err)
		return
	}

	fmt.Printf("[OSINT %s] Shodan summary appended to %s (json: %s)\n", ip, s.outfile, jsonPath)

	// small sleep to be polite in case caller loops over many IPs
	time.Sleep(1 * time.Second)
}

func buildShodanSummaryFromJSON(r io.Reader, ip string) (string, error) {
	var obj map[string]any
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return "", fmt.Errorf("json decode: %w", err)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Shodan results for %s\n", ip))
	b.WriteString("=================================\n\n")

	if hosts, ok := obj["hostnames"].([]any); ok && len(hosts) > 0 {
		names := []string{}
		for _, h := range hosts {
			if s, ok := h.(string); ok && s != "" {
				names = append(names, s)
			}
		}
		if len(names) > 0 {
			b.WriteString("Hostnames: " + strings.Join(names, ", ") + "\n")
		}
	}

	if v, ok := obj["org"].(string); ok && v != "" {
		b.WriteString("Organization: " + v + "\n")
	}
	if v, ok := obj["asn"].(string); ok && v != "" {
		b.WriteString("ASN: " + v + "\n")
	}
	if v, ok := obj["os"].(string); ok && v != "" {
		b.WriteString("OS: " + v + "\n")
	}
	if v, ok := obj["country_name"].(string); ok && v != "" {
		b.WriteString("Country: " + v + "\n")
	}
	if v, ok := obj["city"].(string); ok && v != "" {
		b.WriteString("City: " + v + "\n")
	}

	if loc, ok := obj["location"].(map[string]any); ok {
		lat, lok := helper.ExtractNumberAsFloat(loc, "latitude")
		lon, rok := helper.ExtractNumberAsFloat(loc, "longitude")
		if lok && rok {
			b.WriteString(fmt.Sprintf("Location: %f,%f\n", lat, lon))
		}
	}

	if dataArr, ok := obj["data"].([]any); ok && len(dataArr) > 0 {
		b.WriteString("\nOpen services:\n")
		for _, e := range dataArr {
			if m, ok := e.(map[string]any); ok {
				port := helper.ExtractInt(m, "port")
				prod := helper.ExtractString(m, "product")
				banner := helper.ExtractString(m, "data")
				if port != 0 {
					b.WriteString(fmt.Sprintf("- Port %d", port))
				} else {
					b.WriteString("- (unknown port)")
				}
				if prod != "" {
					b.WriteString(fmt.Sprintf(" — %s", prod))
				}
				b.WriteString("\n")
				if banner != "" {
					sn := banner
					if len(sn) > 512 {
						sn = sn[:512] + "…"
					}
					b.WriteString(fmt.Sprintf("  Banner: %s\n", sn))
				}
			}
		}
	}

	return b.String(), nil
}
