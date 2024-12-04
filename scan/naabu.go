package scan

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type Naabu struct {
	Proxy     string
	RateLimit int32
	ScanPath  string
}

func (d *Naabu) Info(url string) {
	fmt.Println("[+] Running Naabu on", url)
}

func (d *Naabu) Configure(c interface{}) {
	d.Proxy = c.(map[string]interface{})["Proxy"].(string)
	d.RateLimit = c.(map[string]interface{})["RateLimit"].(int32)
	d.ScanPath = c.(map[string]interface{})["ScanPath"].(string)
}

func (d *Naabu) Run(url string) {

	var fullScan string
	options := runner.Options{
		Host:     goflags.StringSlice{url},
		TopPorts: "1000",
		ScanType: "s",
		Rate:     int(d.RateLimit),
		Proxy:    d.Proxy,
		OnResult: func(hr *result.HostResult) {
			var stringToAdd string
			for _, port := range hr.Ports {
				stringToAdd += fmt.Sprintf("%v/%v\n", port.Port, port.Protocol)
			}

			fullScan = fullScan + stringToAdd
		},
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		panic(err)
	}
	defer naabuRunner.Close()
	ctx := context.Background()
	naabuRunner.RunEnumeration(ctx)

	err = ioutil.WriteFile(d.ScanPath, []byte(fullScan), 0644)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[SCAN %s] Naabu scan for %s completed\n\t=>(stored in %s)\n\n", url, d.ScanPath)
}
