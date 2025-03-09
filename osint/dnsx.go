package osint

import (
	"bytes"
	"encoding/json"
	"fmt"
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

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, []byte(jsonStr), "", "\t")
	if error != nil {
		panic(err)
	}

	fo, err := os.Create(d.outfile)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()

	if _, err := fo.Write(prettyJSON.Bytes()); err != nil {
		panic(err)
	}

	fmt.Printf("[OSINT %s] Dnsx results are stored in %s\n", domain, d.outfile)
}
