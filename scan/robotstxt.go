package scan

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"evil.djnn.sh/djnn/yellow/helpers"
)

type RobotsTxt struct {
	Proxy string
}

func (d *RobotsTxt) Info(url string) {
	fmt.Println("[+] Running RobotsTxt on", url)
}

func (d *RobotsTxt) Configure(c any) {
	d.Proxy = c.(map[string]any)["Proxy"].(string)
}

func (d *RobotsTxt) Run(domain string) {
	domain = strings.TrimSuffix(domain, "/")

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
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("%v", err)
			}
			sb := string(body)
			fmt.Println(sb)

		} else {
			fmt.Println("----- Sorry, got 404 status code for robots.txt ----- ")
		}
		resp.Body.Close()
	}

	fmt.Printf("[SCAN %s] RobotsTxt scan for %s completed\n\n", domain, domain)
}
