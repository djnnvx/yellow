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

type Gobuster struct{}

func (*Gobuster) Name() string { return "gobuster" }

func (*Gobuster) Run(ctx *core.Context) error {
	fmt.Println("Running gobuster on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	rawUrl := ctx.Domain
	globalOpts := libgobuster.Options{}
	globalOpts.Wordlist = ctx.Wordlist
	globalOpts.OutputFilename = ctx.ScanPath + "/gobuster.txt"
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
		return nil
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
		return nil
	}

	mainContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := cli.Gobuster(mainContext, &globalOpts, plugin, log); err != nil {

		var wErr *gobusterdir.WildcardError
		if errors.As(err, &wErr) {
			fmt.Printf("%v.\nTo continue please exclude the status code or the length\n", wErr)
			fmt.Printf("\nSince gobuster cannot make the difference between good and bad urls, it will be skipped.\n\n")
			return nil
		}
	}

	fmt.Printf("[SCAN %s] Gobuster scan for %s completed\n\n", rawUrl, rawUrl)
	return nil
}
