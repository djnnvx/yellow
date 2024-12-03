package osint

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type Subfinder struct {
	outfile string
}

func (s *Subfinder) Info(url string) {
	fmt.Println("[+] Running subfinder on", url)
}

func (s *Subfinder) Configure(c interface{}) {
	s.outfile = c.(map[string]interface{})["outfile"].(string)
}

func (s *Subfinder) Run(domain string) {
	subfinderOpts := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            15, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 3,  // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		// ResultCallback: func(s *resolve.HostEntry) {
		// callback function executed after each unique subdomain is found
		// },
	}

	log.SetFlags(0)

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Fatalf("failed to create subfinder runner: %v", err)
	}

	output := &bytes.Buffer{}
	if err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{output}); err != nil {
		log.Fatalf("failed to enumerate single domain: %v", err)
	}

	fo, err := os.Create(s.outfile)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()

	if _, err := fo.Write(output.Bytes()); err != nil {
		panic(err)
	}

	fmt.Printf("[OSINT %s] Subfinder are stored in %s\n\n", domain, s.outfile)
}
