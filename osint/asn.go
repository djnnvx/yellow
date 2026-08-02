package osint

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"evil.djnn.sh/djnn/yellow/core"
	helper "evil.djnn.sh/djnn/yellow/helpers"
)

type ASNRecord struct {
	Input           string `json:"input"`
	IP              string `json:"ip"`
	ASN             string `json:"asn"`
	Org             string `json:"org,omitempty"`
	Country         string `json:"country,omitempty"`
	Registry        string `json:"registry,omitempty"`
	Prefix          string `json:"prefix"`
	HostingProvider bool   `json:"hosting_provider"`
	Source          string `json:"source"`
}

type asnOrigin struct {
	ASN      string
	Prefix   string
	Country  string
	Registry string
	Org      string
}

type asnProvider struct {
	name  string
	query func(reversed string) string
	parse func(txt string) (asnOrigin, bool)
}

var asnProviders = []asnProvider{
	{
		name:  "cymru",
		query: func(r string) string { return r + ".origin.asn.cymru.com" },
		parse: parseCymruOrigin,
	},
	{
		name:  "shadowserver",
		query: func(r string) string { return r + ".origin.asn.shadowserver.org" },
		parse: parseShadowserverOrigin,
	},
}

type ASN struct {
	lookupTXT func(string) ([]string, error)
	providers []asnProvider
}

func (*ASN) Name() string { return "asn" }

func (a *ASN) Run(ctx *core.Context) error {
	fmt.Println("[+] Running asn lookup on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	if a.lookupTXT == nil {
		a.lookupTXT = net.LookupTXT
	}
	if a.providers == nil {
		a.providers = asnProviders
	}

	records := []ASNRecord{}
	seenIP := map[string]bool{}
	asnOrgs := map[string]string{}

	for _, candidate := range ctx.Domains {
		input := strings.TrimSpace(candidate)
		if input == "" {
			continue
		}

		ip := input
		if net.ParseIP(ip) == nil {
			addrs, err := net.LookupHost(ip)
			if err != nil || len(addrs) == 0 {
				continue
			}
			ip = addrs[0]
		}

		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			fmt.Printf("[!] asn: %s is not IPv4, skipping\n", ip)
			continue
		}
		if seenIP[ip] {
			continue
		}
		seenIP[ip] = true

		origin, source, ok := a.origin(ip)
		if !ok {
			continue
		}

		org := origin.Org
		if org == "" {
			org = a.asnOrg(origin.ASN, asnOrgs)
		}

		rec := ASNRecord{
			Input:           input,
			IP:              ip,
			ASN:             "AS" + origin.ASN,
			Org:             org,
			Country:         origin.Country,
			Registry:        origin.Registry,
			Prefix:          origin.Prefix,
			HostingProvider: isHostingProvider(org, parsed),
			Source:          source,
		}
		records = append(records, rec)

		flag := ""
		if rec.HostingProvider {
			flag = " [provider-owned, NOT client scope]"
		}
		fmt.Printf("[OSINT %s] %s %s %s%s\n", ip, rec.ASN, rec.Prefix, org, flag)
	}

	outfile := fmt.Sprintf("%s/asn.json", ctx.ScanPath)
	data, _ := json.MarshalIndent(records, "", "\t")
	if err := os.WriteFile(outfile, data, 0644); err != nil {
		fmt.Printf("[!] asn: could not write %s: %v\n", outfile, err)
	}

	uniqueASN := map[string]bool{}
	hosted := 0
	for _, r := range records {
		uniqueASN[r.ASN] = true
		if r.HostingProvider {
			hosted++
		}
	}
	fmt.Printf("[OSINT %s] asn: %d prefix(es) across %d ASN(s), %d provider-owned, in %s\n\n",
		ctx.Domain, len(records), len(uniqueASN), hosted, outfile)
	return nil
}

func (a *ASN) origin(ip string) (asnOrigin, string, bool) {
	reversed := reverseIPv4(ip)
	if reversed == "" {
		return asnOrigin{}, "", false
	}

	for _, p := range a.providers {
		txts, err := a.lookupTXT(p.query(reversed))
		if err != nil || len(txts) == 0 {
			continue
		}
		for _, txt := range txts {
			if origin, ok := p.parse(txt); ok {
				return origin, p.name, true
			}
		}
	}
	return asnOrigin{}, "", false
}

func (a *ASN) asnOrg(asn string, cache map[string]string) string {
	if org, ok := cache[asn]; ok {
		return org
	}
	txts, err := a.lookupTXT("AS" + asn + ".asn.cymru.com")
	org := ""
	if err == nil {
		for _, txt := range txts {
			if name := parseCymruASName(txt); name != "" {
				org = name
				break
			}
		}
	}
	cache[asn] = org
	return org
}

// "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
func parseCymruOrigin(txt string) (asnOrigin, bool) {
	f := splitCymru(txt)
	if len(f) < 2 || f[0] == "" || f[1] == "" {
		return asnOrigin{}, false
	}
	o := asnOrigin{ASN: firstField(f[0]), Prefix: f[1]}
	if len(f) > 2 {
		o.Country = f[2]
	}
	if len(f) > 3 {
		o.Registry = f[3]
	}
	return o, o.ASN != ""
}

// "15169 | 8.8.8.0/24 | AS15169 | US | Google LLC"
func parseShadowserverOrigin(txt string) (asnOrigin, bool) {
	f := splitCymru(txt)
	if len(f) < 2 || f[0] == "" || f[1] == "" {
		return asnOrigin{}, false
	}
	o := asnOrigin{ASN: firstField(f[0]), Prefix: f[1]}
	if len(f) > 3 {
		o.Country = f[3]
	}
	if len(f) > 4 {
		o.Org = f[4]
	}
	return o, o.ASN != ""
}

// "20473 | US | arin | 2001-05-11 | AS-VULTR - The Constant Company, LLC, US"
func parseCymruASName(txt string) string {
	f := splitCymru(txt)
	if len(f) < 5 {
		return ""
	}
	return f[4]
}

func splitCymru(txt string) []string {
	parts := strings.Split(txt, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// an IP can be announced by several ASNs: "1234 5678 | prefix | ..."
func firstField(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

func reverseIPv4(ip string) string {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

// cdncheck misses several hosting providers (Vultr among them), so the AS name
// is checked too.
var hostingKeywords = []string{
	"amazon", "aws", "google", "microsoft", "azure", "oracle", "alibaba",
	"digitalocean", "linode", "vultr", "constant company", "hetzner", "ovh",
	"scaleway", "leaseweb", "rackspace", "cloudflare", "akamai", "fastly",
	"contabo", "upcloud", "ionos", "godaddy", "hostinger",
}

func isHostingProvider(org string, ip net.IP) bool {
	if helper.LookupCDN(ip) != nil {
		return true
	}
	lower := strings.ToLower(org)
	for _, kw := range hostingKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
