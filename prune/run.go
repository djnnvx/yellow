package prune

import (
	"fmt"

	"evil.djnn.sh/djnn/yellow/core"
	helper "evil.djnn.sh/djnn/yellow/helpers"
)

type PruneOpts struct {
	Proxy         string
	DryRun        bool
	ForceInsecure bool

	InFilePath  string
	OutFilePath string
}

func (opts *PruneOpts) Run() {

	helper.CheckProxy(opts.Proxy)
	helper.DisplayNetInfo()

	results := make([]string, 0)
	scanner := helper.LoadTargetFile(opts.InFilePath)
	defer scanner.Close()

	for scanner.Scan() {
		targetDomain := scanner.Text()

		if target, ok := helper.ResolveWebTarget(targetDomain, opts.ForceInsecure); ok {
			fmt.Printf("[+] %s is alive (%s)!\n", targetDomain, target)
			results = append(results, targetDomain)
		}
	}

	if err := core.WriteLines(opts.OutFilePath, results); err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}

	fmt.Printf("[+] Done. Saved %d alive domains\n", len(results))
}
