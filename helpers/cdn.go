package helper

import (
	"fmt"
	"net"
	"sync"

	"github.com/projectdiscovery/cdncheck"
)

type CDNInfo struct {
	Type     string `json:"type"` // cdn | waf | cloud
	Provider string `json:"provider"`
}

var (
	cdnOnce   sync.Once
	cdnClient *cdncheck.Client
)

func LookupCDN(ip net.IP) *CDNInfo {
	cdnOnce.Do(func() {
		client, err := cdncheck.NewWithOpts(3, nil)
		if err != nil {
			fmt.Printf("[!] cdncheck: unavailable, edge detection disabled: %v\n", err)
			return
		}
		cdnClient = client
	})

	if cdnClient == nil || ip == nil {
		return nil
	}

	matched, provider, itemType, err := cdnClient.Check(ip)
	if err != nil || !matched {
		return nil
	}
	return &CDNInfo{Type: itemType, Provider: provider}
}

// SkipPortScan only skips WAFs. cdncheck files ordinary GCE compute under
// "cdn/google", so skipping on cdn would drop real origins.
func SkipPortScan(info *CDNInfo) bool {
	return info != nil && info.Type == "waf"
}
