package scan

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
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

func (d *RobotsTxt) Configure(c interface{}) {
	d.Proxy = c.(map[string]interface{})["Proxy"].(string)
}

func (d *RobotsTxt) Run(domain string) {
	domain = strings.TrimSuffix(domain, "/")

	transport := helper.GetHttpTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{
		Transport: transport,
	}

	for _, u := range getUrls(domain) {
		req, err := http.NewRequest("GET", fmt.Sprint(u, "/robots.txt"), nil)
		req.Header.Add("User-Agent", helper.GetUserAgent())

		resp, err := client.Do(req)

		if err != nil {
			fmt.Printf("%v", err)
		}

		if resp != nil && resp.StatusCode != http.StatusNotFound {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("%v", err)
			}
			sb := string(body)
			fmt.Println(sb)

		} else {
			fmt.Println("----- Sorry, got 404 status code for robots.txt ----- ")
		}
	}

	fmt.Printf("[SCAN %s] RobotsTxt scan for %s completed\n\n", domain)
}
