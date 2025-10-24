package prune

import (
	"fmt"
	"os"
	"strings"

	helper "evil.djnn.sh/djnn/yellow/helpers"
)

type PruneOpts struct {
	proxy         string
	dryRun        bool
	forceInsecure bool

	inFilePath  string
	outFilePath string
}

func (opts *PruneOpts) SetInFilePath(data string) {
	opts.inFilePath = data
}

func (opts *PruneOpts) SetOutFilePath(data string) {
	opts.outFilePath = data
}

func (opts *PruneOpts) SetForceInsecure(data bool) {
	opts.forceInsecure = data
}

func (opts *PruneOpts) SetProxy(data string) {
	opts.proxy = data
}

func (opts *PruneOpts) SetDryRun(data bool) {
	opts.dryRun = data
}

func (opts *PruneOpts) Run() {

	helper.CheckProxy(opts.proxy)
	helper.DisplayNetInfo()

	results := make([]string, 0)
	scanner := helper.LoadTargetFile(opts.inFilePath)
	defer scanner.Close()

	for scanner.Scan() {
		targetDomain := scanner.Text()
		httpAddr := "https://" + targetDomain
		if opts.forceInsecure {
			httpAddr = "http://" + targetDomain
		}

		if !helper.HasUnavailableWebInterface(httpAddr) {
			fmt.Printf("[+] %s is alive !\n", targetDomain)
			results = append(results, targetDomain)
		}
	}

	content := strings.Join(results, "\n")
	err := os.WriteFile(opts.outFilePath, []byte(content), 0644)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}

	fmt.Printf("[+] Done. Saved %d alive domains\n", len(results))
}
