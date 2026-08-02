package scan

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"evil.djnn.sh/djnn/yellow/core"
	"evil.djnn.sh/djnn/yellow/helpers"
	"github.com/OJ/gobuster/v3/cli"
	"github.com/OJ/gobuster/v3/gobusterdir"
	"github.com/OJ/gobuster/v3/libgobuster"
)

type Gobuster struct {
	MaxURLs int
}

func (*Gobuster) Name() string { return "gobuster" }

func (g *Gobuster) Run(ctx *core.Context) error {
	fmt.Println("Running gobuster on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	roots := capURLs(dirRoots(ctx.URLs), g.MaxURLs, "gobuster")
	if len(roots) == 0 {
		roots = []string{ctx.Domain}
	}

	for i, root := range roots {
		outfile := ctx.ScanPath + "/gobuster.txt"
		if len(roots) > 1 {
			outfile = fmt.Sprintf("%s/gobuster-%d.txt", ctx.ScanPath, i+1)
		}
		bustDir(ctx, root, outfile)
	}
	return nil
}

func bustDir(ctx *core.Context, rawUrl, outfile string) {
	globalOpts := libgobuster.Options{}
	globalOpts.Wordlist = ctx.Wordlist
	globalOpts.OutputFilename = outfile
	globalOpts.Quiet = false
	globalOpts.Threads = 50

	globalOpts.WordlistOffset = 0
	globalOpts.Debug = false
	globalOpts.DiscoverPatternFile = ""
	globalOpts.Patterns = make([]string, 0)
	globalOpts.DiscoverPatterns = make([]string, 0)
	globalOpts.NoError = false
	globalOpts.NoProgress = false
	globalOpts.Delay = time.Second

	u, err := url.Parse(rawUrl)
	if err != nil {
		fmt.Printf("[!] gobuster: invalid URL %s: %v\n", rawUrl, err)
		return
	}

	pluginOpts := gobusterdir.NewOptions()
	pluginOpts.Proxy = ctx.Proxy
	pluginOpts.NoTLSValidation = ctx.Insecure
	pluginOpts.UserAgent = helper.GetUserAgent()
	pluginOpts.URL = u
	pluginOpts.Method = "GET"
	pluginOpts.Timeout = time.Second * 5

	ssc, _ := libgobuster.ParseCommaSeparatedInt("302,404,500")
	pluginOpts.StatusCodesBlacklistParsed = ssc

	log := libgobuster.NewLogger(globalOpts.Debug)
	plugin, err := gobusterdir.New(&globalOpts, pluginOpts, log)
	if err != nil {
		fmt.Printf("[!] gobuster: cannot load plugin: %v\n", err)
		return
	}

	mainContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := cli.Gobuster(mainContext, &globalOpts, plugin, log); err != nil {

		var wErr *gobusterdir.WildcardError
		if errors.As(err, &wErr) {
			fmt.Printf("%v.\nTo continue please exclude the status code or the length\n", wErr)
			fmt.Printf("\nSince gobuster cannot make the difference between good and bad urls, it will be skipped.\n\n")
			return
		}
	}

	fmt.Printf("[SCAN %s] Gobuster scan for %s completed\n\n", rawUrl, rawUrl)
}
