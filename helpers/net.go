package helper

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func ParseDomain(website string) string {
	if strings.HasPrefix(website, "http") {
		parsedUrl, err := url.Parse(website)
		if err != nil {
			fmt.Printf("%s", err)
		}

		website = parsedUrl.Host
	}

	return website
}

func GetHttpTransport() *http.Transport {
	var proxy = os.Getenv("HTTP_PROXY")
	url, err := url.Parse(proxy)

	if proxy != "" && err == nil {
		return &http.Transport{
			DisableKeepAlives: true,
			Proxy:             http.ProxyURL(url),
		}
	}
	return &http.Transport{}
}

func GetUserAgent() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
}

func GetCurrentIP() string {
	ht := GetHttpTransport()
	ua := GetUserAgent()

	cli := &http.Client{
		Transport: ht,
	}

	req, err := http.NewRequest("GET", "http://icanhazip.com", nil)
	if err != nil {
		fmt.Printf("[!] Could not query public IP address: %s\n", err.Error())
		return "127.0.0.1" // if the service is offline or not reachable, we should be able to keep going
	}

	req.Header.Add("User-Agent", ua)
	resp, err := cli.Do(req)

	if err != nil || resp == nil {
		fmt.Printf("[!] Could not query public IP address: %s\n", err.Error())
		return ""
	}

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[!] Could not IP address: %s\n", err.Error())
		return ""
	}

	return string(result)
}

func DisplayNetInfo() {
	ip := GetCurrentIP()
	ua := GetUserAgent()

	if ip == "" {
		os.Exit(1)
	}

	fmt.Println("[~] Current Public IP: " + ip)
	fmt.Println("[~] Prefered User-Agent: " + ua)
}

func CheckProxy(proxy string) {
	os.Setenv("HTTP_PROXY", proxy)
	os.Setenv("HTTPS_PROXY", proxy)

	if proxy != "" {
		fmt.Println("[+] Proxy configuration: %s", proxy)
	} else {
		fmt.Println("[+] No proxy has been set")
	}
}
