package helper

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"os"
	"strings"
)

const HttpTimeout = 15 * time.Second

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

func GetHttpClient(insecure bool) *http.Client {
	transport := GetHttpTransport()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   HttpTimeout,
	}
}

func GetUserAgent() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
}

func GetCurrentIP() string {
	ua := GetUserAgent()

	cli := GetHttpClient(false)

	req, err := http.NewRequest("GET", "http://icanhazip.com", nil)
	if err != nil {
		fmt.Printf("[!] Could not query public IP address: %s\n", err.Error())
		return "127.0.0.1" // if the service is offline or not reachable, we should be able to keep going
	}

	req.Header.Add("User-Agent", ua)
	resp, err := cli.Do(req)

	if err != nil || resp == nil {
		fmt.Printf("[!] Could not query public IP address: %v\n", err)
		return "127.0.0.1" // service offline or unreachable, we should be able to keep going
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[!] Could not read public IP address: %v\n", err)
		return "127.0.0.1"
	}

	return strings.TrimSpace(string(result))
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

	client := GetHttpClient(true)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return true
	}
	req.Header.Add("User-Agent", GetUserAgent())
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return true
	}
	defer resp.Body.Close()

	return resp.StatusCode >= http.StatusBadGateway
}
