package osint

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"evil.djnn.sh/djnn/yellow/core"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type Subfinder struct{}

func (*Subfinder) Name() string { return "subfinder" }

func (*Subfinder) Run(ctx *core.Context) error {
	fmt.Println("[+] Running subfinder on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	outfile := fmt.Sprintf("%s/subfinder.txt", ctx.ScanPath)

	subfinderOpts := &runner.Options{
		Threads:            10, // number of threads to use for active enumerations
		Timeout:            15, // seconds to wait for sources to respond
		MaxEnumerationTime: 3,  // max minutes to wait for enumeration
	}

	log.SetFlags(0)

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		fmt.Printf("[!] Subfinder: failed to create runner: %v\n", err)
		return nil
	}

	output := &bytes.Buffer{}
	_, err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), ctx.Domain, []io.Writer{output})
	if err != nil {
		fmt.Printf("[!] Subfinder: failed to enumerate %s: %v\n", ctx.Domain, err)
		return nil
	}

	fo, err := os.Create(outfile)
	if err != nil {
		fmt.Printf("[!] Subfinder: failed to create %s: %v\n", outfile, err)
		return nil
	}
	defer fo.Close()

	if _, err := fo.Write(output.Bytes()); err != nil {
		fmt.Printf("[!] Subfinder: failed to write %s: %v\n", outfile, err)
		return nil
	}

	fmt.Printf("[OSINT %s] Subfinder are stored in %s\n\n", ctx.Domain, outfile)
	return nil
}
