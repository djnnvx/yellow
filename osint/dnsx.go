package osint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

type Dnsx struct {
	outfile string
	proxy   string
}

func (d *Dnsx) Info(url string) {
	fmt.Println("[+] Running dnsx on ", url)
}

func (d *Dnsx) Configure(c any) {
	d.outfile = c.(map[string]any)["outfile"].(string)
	d.proxy = c.(map[string]any)["proxy"].(string)
}

func (d *Dnsx) Run(domain string) {
	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	result, err := dnsClient.Lookup(domain)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	for idx, msg := range result {
		fmt.Printf("%d: %s\n", idx+1, msg)
	}

	rawResp, err := dnsClient.QueryOne(domain)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	jsonStr, err := rawResp.JSON()
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	// Try to unmarshal the DNSX JSON response into a map so we can add TXT records.
	var obj map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		// If unmarshalling fails, start with an empty object and preserve the original JSON under "raw" key.
		fmt.Printf("warning: failed to unmarshal DNSX JSON: %v\n", err)
		obj = map[string]any{
			"raw": jsonStr,
		}
	}

	txts, txtErr := net.LookupTXT(domain)
	if txtErr != nil {
		fmt.Printf("warning: failed to lookup TXT records for %s: %v\n", domain, txtErr)
		txts = []string{}
	}
	obj["TXTs"] = txts

	modifiedJSON, err := json.Marshal(obj)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	var prettyJSON bytes.Buffer
	if indentErr := json.Indent(&prettyJSON, modifiedJSON, "", "\t"); indentErr != nil {
		fmt.Printf("err: %v\n", indentErr)
		return
	}

	fo, err := os.Create(d.outfile)
	if err != nil {
		fmt.Printf("[!] Dnsx: failed to create %s: %v\n", d.outfile, err)
		return
	}
	defer fo.Close()

	if _, err := fo.Write(prettyJSON.Bytes()); err != nil {
		fmt.Printf("[!] Dnsx: failed to write %s: %v\n", d.outfile, err)
		return
	}

	fmt.Printf("[OSINT %s] Dnsx results are stored in %s\n", domain, d.outfile)
}
