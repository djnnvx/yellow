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

	"github.com/go-rod/rod/lib/launcher"
)

const HttpTimeout = 15 * time.Second

const MaxBodySize = 10 << 20

// ReadCappedBody stops at MaxBodySize so a target cannot pick our memory usage.
func ReadCappedBody(r io.Reader) (body []byte, truncated bool, err error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBodySize+1))
	if len(b) > MaxBodySize {
		return b[:MaxBodySize], true, err
	}
	return b, false, err
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

// SystemChromePath returns an installed Chrome/Chromium, or "" to let the
// headless tooling download its own.
func SystemChromePath() string {
	path, ok := launcher.LookPath()
	if !ok {
		return ""
	}
	return path
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

	result, _, err := ReadCappedBody(resp.Body)
	if err != nil {
		fmt.Printf("[!] Could not read public IP address: %v\n", err)
		return "127.0.0.1"
	}

	return strings.TrimSpace(string(result))
}

func DisplayNetInfo() {
	ip := GetCurrentIP()
	ua := GetUserAgent()

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

// ResolveWebTarget probes https first and falls back to http, so a host that
// only serves plaintext is still scanned instead of skipped.
func ResolveWebTarget(domain string, forceInsecure bool) (string, bool) {
	return resolveWebTarget(domain, forceInsecure, HasUnavailableWebInterface)
}

func resolveWebTarget(domain string, forceInsecure bool, unavailable func(string) bool) (string, bool) {
	schemes := []string{"https://", "http://"}
	if forceInsecure {
		schemes = []string{"http://"}
	}
	for _, scheme := range schemes {
		if target := scheme + domain; !unavailable(target) {
			return target, true
		}
	}
	return "", false
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
