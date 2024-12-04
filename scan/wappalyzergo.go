package scan

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"

	"evil.djnn.sh/djnn/yellow/helpers"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type WappalyzerGo struct {
	Proxy string
}

func (d *WappalyzerGo) Info(url string) {
	fmt.Println("[+] Running WappalyzerGo on", url)
}

func (d *WappalyzerGo) Configure(c interface{}) {
	d.Proxy = c.(map[string]interface{})["Proxy"].(string)
}

func (d *WappalyzerGo) Run(url string) {

	transport := helper.GetHttpTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("User-Agent", helper.GetUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%v", err)
	}

	if resp != nil {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("%v", err)
		}

		wappalyzerClient, err := wappalyzer.New()
		fingerprints := wappalyzerClient.Fingerprint(resp.Header, body)
		fmt.Printf("%v\n", fingerprints)
	}

	fmt.Printf("[SCAN %s] WappalyzerGo scan for %s completed\n\n", url, url)
}
