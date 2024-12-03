package osint

import (
	"fmt"

	"github.com/projectdiscovery/httpx/runner"
)

type Httpx struct {
	InputFile  string
	Proxy      string
	OutDirPath string
	RateLimit  int32
}

func (h *Httpx) Info(url string) {
	fmt.Println("[+] Running httpx on ", url)
}

func (h *Httpx) Configure(c interface{}) {
	h.OutDirPath = c.(map[string]interface{})["OutDirPath"].(string)
	h.InputFile = c.(map[string]interface{})["InputFile"].(string)
	h.Proxy = c.(map[string]interface{})["Proxy"].(string)
	h.RateLimit = c.(map[string]interface{})["RateLimit"].(int32)
}

func (h *Httpx) Run(domain string) {
	options := runner.Options{
		Methods:          "GET",
		InputFile:        h.InputFile,
		HTTPProxy:        h.Proxy,
		StoreResponseDir: h.OutDirPath,
		Screenshot:       true,
		RateLimit:        int(h.RateLimit),
	}

	if err := options.ValidateOptions(); err != nil {
		panic(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		panic(err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
	fmt.Printf("[OSINT %s] httpx completed.\n", domain)
}
