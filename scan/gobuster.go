package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"evil.djnn.sh/djnn/yellow/helpers"
	"github.com/OJ/gobuster/v3/cli"
	"github.com/OJ/gobuster/v3/gobusterdir"
	"github.com/OJ/gobuster/v3/libgobuster"
)

type Gobuster struct {
	scanPath  string
	proxy     string
	wordlist  string
	insecure  bool
	rateLimit int32
}

func (s *Gobuster) Info(website string) {
	fmt.Println("Running gobuster on", website)
}

func (g *Gobuster) Configure(c any) {

	g.scanPath = c.(map[string]any)["scanPath"].(string)
	g.proxy = c.(map[string]any)["proxy"].(string)
	g.wordlist = c.(map[string]any)["wordlist"].(string)
	g.insecure = c.(map[string]any)["insecure"].(bool)
	g.rateLimit = c.(map[string]any)["rateLimit"].(int32)
}

func (g *Gobuster) Run(url string) {

	globalOpts := libgobuster.NewOptions()
	globalOpts.Wordlist = g.wordlist
	globalOpts.OutputFilename = g.scanPath + "/gobuster.txt"
	globalOpts.Quiet = false
	globalOpts.Threads = 50

	pluginOpts := gobusterdir.NewOptionsDir()
	pluginOpts.Proxy = g.proxy
	pluginOpts.NoTLSValidation = g.insecure
	pluginOpts.UserAgent = helper.GetUserAgent()
	pluginOpts.URL = url
	pluginOpts.Method = "GET"
	pluginOpts.Timeout = time.Second * 5

	ssc, _ := libgobuster.ParseCommaSeparatedInt("302,404,500")
	pluginOpts.StatusCodesBlacklistParsed = ssc

	plugin, err := gobusterdir.NewGobusterDir(globalOpts, pluginOpts)
	if err != nil {
		panic(err)
	}

	mainContext, _ := context.WithCancel(context.Background())
	log := libgobuster.NewLogger(globalOpts.Debug)
	if err := cli.Gobuster(mainContext, globalOpts, plugin, log); err != nil {

		var wErr *gobusterdir.ErrWildcard
		if errors.As(err, &wErr) {
			fmt.Printf("%v.\nTo continue please exclude the status code or the length\n", wErr)
			fmt.Printf("\nSince gobuster cannot make the difference between good and bad urls, it will be skipped.\n\n")
			return
		}
	}

	fmt.Printf("[SCAN %s] Gobuster scan for %s completed\n\n", url, url)
}
