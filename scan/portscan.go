package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	nervascan "github.com/praetorian-inc/nerva/pkg/scan"
)

type PortScanResult struct {
	Target    string       `json:"target"`
	ScannedAt time.Time    `json:"scanned_at"`
	OpenPorts []PortResult `json:"open_ports"`
}

type SecurityFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

type PortResult struct {
	Port     int               `json:"port"`
	Proto    string            `json:"proto"`
	Service  string            `json:"service,omitempty"`
	Version  string            `json:"version,omitempty"`
	Findings []SecurityFinding `json:"findings,omitempty"`
}

type PortScanner struct {
	scanPath string
	ports    string
	timeout  time.Duration
	workers  int
}

func (opts ScanOpts) runPortScan() {
	ps := PortScanner{
		scanPath: opts.scanPath + "/" + opts.domain,
		ports:    opts.ports,
		timeout:  2 * time.Second,
		workers:  100,
	}
	fmt.Printf("[+] Running port scan on %s\n", opts.domain)
	if !opts.dryRun {
		if err := os.MkdirAll(ps.scanPath, 0755); err != nil {
			fmt.Printf("[!] port scan: could not create %s: %v\n", ps.scanPath, err)
			return
		}
		ps.Run(opts.domain)
	}
}

func (p *PortScanner) Run(host string) {
	if net.ParseIP(host) == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			fmt.Printf("err: could not resolve %s to an IP: %v\n", host, err)
			return
		}
		host = addrs[0]
	}

	ports, err := parsePorts(p.ports)
	if err != nil {
		fmt.Printf("[!] invalid ports spec: %v\n", err)
		return
	}

	open := p.tcpScan(host, ports)
	results := p.fingerprint(host, open)

	out := PortScanResult{
		Target:    host,
		ScannedAt: time.Now().UTC(),
		OpenPorts: results,
	}

	data, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(p.scanPath+"/portscan.json", data, 0644); err != nil {
		fmt.Printf("[!] port scan: could not write %s/portscan.json: %v\n", p.scanPath, err)
	}

	fmt.Printf("[SCAN %s] port scan done — %d open ports\n\n", host, len(open))
}

func (p *PortScanner) tcpScan(host string, ports []int) []int {
	var mu sync.Mutex
	var open []int
	sem := make(chan struct{}, p.workers)
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, p.timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}

func (p *PortScanner) fingerprint(host string, openPorts []int) []PortResult {
	if len(openPorts) == 0 {
		return nil
	}

	// resolve hostname once
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return fallbackResults(openPorts)
	}

	ip := addrs[0].To4()
	if ip == nil {
		ip = addrs[0]
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fallbackResults(openPorts)
	}

	targets := make([]plugins.Target, len(openPorts))
	for i, port := range openPorts {
		targets[i] = plugins.Target{
			Address: netip.AddrPortFrom(addr, uint16(port)),
			Host:    host,
		}
	}

	cfg := nervascan.Config{
		DefaultTimeout: p.timeout,
		Misconfigs:     true,
	}
	nervaResults, err := nervascan.ScanTargets(context.Background(), targets, cfg)
	if err != nil {
		return fallbackResults(openPorts)
	}

	results := make([]PortResult, 0, len(nervaResults))
	for _, r := range nervaResults {
		var findings []SecurityFinding
		for _, f := range r.SecurityFindings {
			findings = append(findings, SecurityFinding{
				ID:          f.ID,
				Severity:    string(f.Severity),
				Description: f.Description,
				Evidence:    f.Evidence,
			})
		}
		results = append(results, PortResult{
			Port:     r.Port,
			Proto:    "tcp",
			Service:  r.Protocol,
			Version:  r.Version,
			Findings: findings,
		})
	}
	return results
}

func fallbackResults(openPorts []int) []PortResult {
	results := make([]PortResult, len(openPorts))
	for i, port := range openPorts {
		results[i] = PortResult{Port: port, Proto: "tcp"}
	}
	return results
}

func parsePorts(spec string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo > hi {
				return nil, fmt.Errorf("invalid range: %s", part)
			}
			for p := lo; p <= hi; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}
