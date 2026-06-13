package osint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"evil.djnn.sh/djnn/yellow/core"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

type Dnsx struct{}

func (*Dnsx) Name() string { return "dnsx" }

func (*Dnsx) Run(ctx *core.Context) error {
	fmt.Println("[+] Running dnsx on ", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	outfile := fmt.Sprintf("%s/dnsx.json", ctx.ScanPath)
	domain := ctx.Domain

	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return nil
	}

	result, err := dnsClient.Lookup(domain)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return nil
	}
	for idx, msg := range result {
		fmt.Printf("%d: %s\n", idx+1, msg)
	}

	rawResp, err := dnsClient.QueryOne(domain)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return nil
	}

	jsonStr, err := rawResp.JSON()
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return nil
	}

	// Try to unmarshal the DNSX JSON response into a map so we can add TXT records.
	var obj map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		// If unmarshalling fails, preserve the original JSON under "raw".
		fmt.Printf("warning: failed to unmarshal DNSX JSON: %v\n", err)
		obj = map[string]any{"raw": jsonStr}
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
		return nil
	}

	var prettyJSON bytes.Buffer
	if indentErr := json.Indent(&prettyJSON, modifiedJSON, "", "\t"); indentErr != nil {
		fmt.Printf("err: %v\n", indentErr)
		return nil
	}

	fo, err := os.Create(outfile)
	if err != nil {
		fmt.Printf("[!] Dnsx: failed to create %s: %v\n", outfile, err)
		return nil
	}
	defer fo.Close()

	if _, err := fo.Write(prettyJSON.Bytes()); err != nil {
		fmt.Printf("[!] Dnsx: failed to write %s: %v\n", outfile, err)
		return nil
	}

	fmt.Printf("[OSINT %s] Dnsx results are stored in %s\n", domain, outfile)
	return nil
}
