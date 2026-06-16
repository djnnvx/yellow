package cli

type StandardOptions struct {

	// Pentest target, will be the name of the directories created, for instance
	// if no target file is specified for OSINT command, will use that instead.
	// Can be Outfile or OutDir
	OutName string

	// Run a dry-run (test mode)
	RunDry bool

	// Proxy URL (used for the tools supporting it. Other will prompt a warning msg)
	Proxy string

	// Ignore SSL warnings and force http
	UseHttpInsecure bool

	// Requests rate-limit (used for the tools supporting it. Other will prompt a warning msg)
	RateLimit int32

	// Wordlist to use (if any)
	WordlistPath string

	// File containing list of targets (should be a list of IP Addresses or domains)
	TargetFilePath string

	// Run Gobuster directory bruteforce (opt-in)
	Gobuster bool

	// Run TCP port scan + service fingerprinting
	PortScan bool

	// Ports to scan (comma-separated or ranges, e.g. "22,80,443,8000-9000")
	Ports string

	// Run nuclei template-based vulnerability scanning (opt-in; downloads templates on first run)
	Nuclei bool

	// File containing list of emails for credential leak checking
	EmailsFilePath string
}

func GetDefaultOptions() StandardOptions {
	return StandardOptions{
		WordlistPath: "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
		Ports:        "21,22,23,25,53,80,110,135,139,143,161,389,443,445,636,993,995,1099,1433,1521,1723,2375,2376,3000,3268,3269,3306,3389,5000,5432,5672,5900,5985,5986,6379,6443,8000,8080,8081,8111,8112,8443,8888,9000,9081,9090,9092,9200,9300,9443,10250,27017",
	}
}
