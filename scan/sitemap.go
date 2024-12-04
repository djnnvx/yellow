package scan

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"evil.djnn.sh/djnn/yellow/helpers"
)

var GlobalHeaders = []string{"Server", "X-XSS-Protection", "Access-Control-Allow-Credentials", "Content-Security-Policy", "X-Powered-By", "Strict-Transport-Security"}

type Sitemap struct {
	Proxy string
}

func (d *Sitemap) Info(url string) {
	fmt.Println("[+] Running Sitemap on", url)
}

func (d *Sitemap) Configure(c interface{}) {
	d.Proxy = c.(map[string]interface{})["Proxy"].(string)
}

func (d *Sitemap) Run(domain string) {
	domain = strings.TrimSuffix(domain, "/")

	transport := helper.GetHttpTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{
		Transport: transport,
	}

	for _, u := range getUrls(domain) {
		req, err := http.NewRequest("GET", fmt.Sprint(u, "/sitemap.xml"), nil)
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

			for headerName, headerValue := range resp.Header {
				if contains(GlobalHeaders, headerName) {
					fmt.Printf("Found Header: %s | %s \n", headerName, headerValue)
				}
			}
			sb := string(body)
			fmt.Println(sb)

		} else {
			fmt.Println("-----  Sorry, got 404 status code for sitemap.xml -----")
		}
	}

	fmt.Printf("[SCAN %s] Sitemap scan for %s completed\n\n", domain)
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func getUrls(target string) (c []*url.URL) {
	if strings.HasPrefix(target, "http") {
		u, err := url.Parse(target)
		if err == nil {
			c = append(c, u)
		}

		return
	}

	if !strings.HasPrefix(target, "http://") {
		u, err := url.Parse("http://" + target)
		if err == nil {
			c = append(c, u)
		}
	}

	if !strings.HasPrefix(target, "https://") {
		u, err := url.Parse("https://" + target)
		if err == nil {
			c = append(c, u)
		}
	}

	return
}
