package scan

import (
	"fmt"
	"net/http"
	"strings"

	"evil.djnn.sh/djnn/yellow/core"
	"evil.djnn.sh/djnn/yellow/helpers"
)

type RobotsTxt struct{}

func (*RobotsTxt) Name() string { return "robots.txt" }

func (*RobotsTxt) Run(ctx *core.Context) error {
	fmt.Println("[+] Running RobotsTxt on", ctx.Domain)
	if ctx.DryRun {
		return nil
	}

	domain := strings.TrimSuffix(ctx.Domain, "/")

	client := helper.GetHttpClient(true)

	for _, u := range getUrls(domain) {
		req, err := http.NewRequest("GET", fmt.Sprint(u, "/robots.txt"), nil)
		if err != nil {
			fmt.Printf("%v", err)
			continue
		}
		req.Header.Add("User-Agent", helper.GetUserAgent())

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("%v", err)
			continue
		}

		if resp.StatusCode != http.StatusNotFound {
			outfile := fmt.Sprintf("%s/robots.txt", ctx.ScanPath)
			if n, err := core.SaveStream(outfile, resp.Body); err != nil {
				fmt.Printf("[!] robots.txt: could not write %s: %v\n", outfile, err)
			} else {
				fmt.Printf("[SCAN %s] robots.txt: %d bytes in %s\n", domain, n, outfile)
			}
		} else {
			fmt.Println("----- Sorry, got 404 status code for robots.txt ----- ")
		}
		resp.Body.Close()
	}

	fmt.Printf("[SCAN %s] RobotsTxt scan for %s completed\n\n", domain, domain)
	return nil
}
