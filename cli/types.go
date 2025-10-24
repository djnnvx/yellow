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

	// Disable Gobuster run (we dont need it sometimes yk)
	NoGobuster bool
}

func GetDefaultOptions() StandardOptions {
	opts := StandardOptions{
		OutName:         "",
		RunDry:          false,
		Proxy:           "",
		UseHttpInsecure: false,
		RateLimit:       0,
		WordlistPath:    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
		TargetFilePath:  "",
		NoGobuster:      false,
	}

	return opts
}
