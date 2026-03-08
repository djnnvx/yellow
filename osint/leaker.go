package osint

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vflame6/leaker/runner"
)

type Leaker struct {
	outfile        string
	emailsFile     string
	proxy          string
	providerConfig string
}

func (l *Leaker) Info(target string) {
	fmt.Printf("[+] Running leaker for credential leak checking (target: %s)\n", target)
	if l.emailsFile != "" {
		fmt.Printf("    Emails file: %s\n", l.emailsFile)
	}
	if l.providerConfig != "" {
		fmt.Printf("    Provider config: %s\n", l.providerConfig)
	}
}

func (l *Leaker) Configure(c any) {
	cfg := c.(map[string]any)
	l.outfile = cfg["outfile"].(string)
	l.emailsFile = cfg["emailsFile"].(string)
	l.proxy = cfg["proxy"].(string)
	l.providerConfig = os.Getenv("LEAKER_PROVIDER_CONFIG")
}

func (l *Leaker) ShouldRun() bool {
	if l.emailsFile == "" {
		fmt.Println("[!] Leaker: no emails file provided, skipping")
		return false
	}

	if _, err := os.Stat(l.emailsFile); os.IsNotExist(err) {
		fmt.Printf("[!] Leaker: emails file %s does not exist, skipping\n", l.emailsFile)
		return false
	}

	return true
}

func (l *Leaker) Run(target string) {
	emailsReader, err := os.Open(l.emailsFile)
	if err != nil {
		fmt.Printf("[!] Leaker: failed to open emails file: %v\n", err)
		return
	}
	defer emailsReader.Close()

	outFile, err := os.Create(l.outfile)
	if err != nil {
		fmt.Printf("[!] Leaker: failed to create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	opts := &runner.Options{
		Timeout:        60 * time.Second,
		OutputFile:     l.outfile,
		ProviderConfig: l.providerConfig,
		Quiet:          true,
	}

	if l.proxy != "" {
		opts.Proxy = l.proxy
	}

	r, err := runner.NewRunner(opts)
	if err != nil {
		fmt.Printf("[!] Leaker: failed to create runner: %v\n", err)
		return
	}

	err = r.EnumerateMultipleEmails(emailsReader, []io.Writer{outFile})
	if err != nil {
		fmt.Printf("[!] Leaker: enumeration failed: %v\n", err)
		return
	}

	fmt.Printf("[OSINT %s] Leaker results are stored in %s\n", target, l.outfile)
}
