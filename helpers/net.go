package helper

import (
	"crypto/tls"
	"fmt"
	"io"
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

	result, err := io.ReadAll(resp.Body)
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
		fmt.Printf("[+] Proxy configuration: %s\n", proxy)
	} else {
		fmt.Println("[+] No proxy has been set")
	}
}

func HasUnavailableWebInterface(url string) bool {
	url = strings.TrimSuffix(url, "/")

	transport := GetHttpTransport()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return true
	}
	req.Header.Add("User-Agent", GetUserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return true
	}

	if resp == nil || resp.StatusCode >= http.StatusBadGateway {
		return true
	}
	return false
}
