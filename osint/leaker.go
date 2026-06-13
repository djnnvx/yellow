package osint

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"evil.djnn.sh/djnn/yellow/core"
	"github.com/vflame6/leaker/runner"
)

type Leaker struct{}

func (*Leaker) Name() string { return "leaker" }

func (*Leaker) Run(ctx *core.Context) error {
	fmt.Printf("[+] Running leaker for credential leak checking (target: %s)\n", ctx.Domain)

	emailsFile := ctx.EmailsFile
	if emailsFile != "" {
		fmt.Printf("    Emails file: %s\n", emailsFile)
	}

	providerConfig := os.Getenv("LEAKER_PROVIDER_CONFIG")
	if providerConfig != "" {
		fmt.Printf("    Provider config: %s\n", providerConfig)
	}

	if ctx.DryRun {
		return nil
	}

	if emailsFile == "" {
		fmt.Println("[!] Leaker: no emails file provided, skipping")
		return nil
	}
	if _, err := os.Stat(emailsFile); os.IsNotExist(err) {
		fmt.Printf("[!] Leaker: emails file %s does not exist, skipping\n", emailsFile)
		return nil
	}

	outfile := fmt.Sprintf("%s/leaks.txt", ctx.ScanPath)

	emailsReader, err := os.Open(emailsFile)
	if err != nil {
		fmt.Printf("[!] Leaker: failed to open emails file: %v\n", err)
		return nil
	}
	defer emailsReader.Close()

	outFile, err := os.Create(outfile)
	if err != nil {
		fmt.Printf("[!] Leaker: failed to create output file: %v\n", err)
		return nil
	}
	defer outFile.Close()

	opts := &runner.Options{
		Timeout:        60 * time.Second,
		OutputFile:     outfile,
		ProviderConfig: providerConfig,
		Quiet:          true,
	}
	if ctx.Proxy != "" {
		opts.Proxy = ctx.Proxy
	}

	r, err := runner.NewRunner(opts)
	if err != nil {
		fmt.Printf("[!] Leaker: failed to create runner: %v\n", err)
		return nil
	}

	if err := r.EnumerateMultipleTargets(context.Background(), emailsReader, []io.Writer{outFile}); err != nil {
		fmt.Printf("[!] Leaker: enumeration failed: %v\n", err)
		return nil
	}

	fmt.Printf("[OSINT %s] Leaker results are stored in %s\n", ctx.Domain, outfile)
	return nil
}
