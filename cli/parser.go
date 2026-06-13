package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"evil.djnn.sh/djnn/yellow/helpers"
	"evil.djnn.sh/djnn/yellow/osint"
	"evil.djnn.sh/djnn/yellow/prune"
	"evil.djnn.sh/djnn/yellow/scan"
)

func GetParser(opts *StandardOptions) *cobra.Command {

	var pruneCmd = &cobra.Command{
		Use:   "prune",
		Short: "filters a file full of domains",
		Long:  "filters a file full of domains to only get the reachable domains",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {

			if opts.TargetFilePath == "" {
				fmt.Println("[!] Error: target cannot be empty. Please run with --file [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			if opts.OutName == "" {
				fmt.Println("[!] Error: output path cannot be empty. Please run with --out [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			pruneOpts := prune.PruneOpts{}
			pruneOpts.SetProxy(opts.Proxy)
			pruneOpts.SetDryRun(opts.RunDry)
			pruneOpts.SetForceInsecure(opts.UseHttpInsecure)
			pruneOpts.SetInFilePath(opts.TargetFilePath)
			pruneOpts.SetOutFilePath(opts.OutName)

			pruneOpts.Run()
		},
	}

	var fingerprintCmd = &cobra.Command{
		Use:   "fingerprint",
		Short: "Runs fingerprinting against websites",
		Long:  "Runs active fingerprinting (wappalyzergo then cvemap)",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {

			if opts.OutName == "" && opts.TargetFilePath == "" {
				fmt.Println("[!] Error: target cannot be empty. Please run with --target [something] or --file [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			helper.CheckProxy(opts.Proxy)
			helper.DisplayNetInfo()

			if opts.OutName == "" || !helper.Exists(opts.OutName) {
				fmt.Println("[!] collected assets will be sent to current working directory")
			}

			scanOpts := scan.ScanOpts{}
			scanOpts.SetDomain(opts.OutName)
			scanOpts.SetScanPath(opts.OutName)
			scanOpts.SetProxy(opts.Proxy)
			scanOpts.SetDryRun(opts.RunDry)
			scanOpts.SetRateLimit(opts.RateLimit)
			scanOpts.SetWordlistPath(opts.WordlistPath)
			scanOpts.SetForceInsecure(opts.UseHttpInsecure)
			scanOpts.SetGobuster(opts.Gobuster)

			if opts.TargetFilePath == "" {
				scanOpts.Run()
				return
			}

			scanner := helper.LoadTargetFile(opts.TargetFilePath)
			defer scanner.Close()

			for scanner.Scan() {
				targetDomain := scanner.Text()
				scanOpts.SetDomain(targetDomain)
				scanOpts.Fingerprint()
			}
		},
	}

	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Run active scanning tools to perform enumeration",
		Long:  "Runs active scanning (sitemap, robots.txt, tlsx, wappalyzergo, cvemap, httpx, optional gobuster, optional TCP port-scan and optional nuclei)",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {

			if opts.OutName == "" && opts.TargetFilePath == "" {
				fmt.Println("[!] Error: target cannot be empty. Please run with --target [something] or --file [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			helper.CheckProxy(opts.Proxy)
			helper.DisplayNetInfo()

			if opts.OutName == "" || !helper.Exists(opts.OutName) {
				fmt.Println("[!] collected assets will be sent to current working directory")
			}

			scanOpts := scan.ScanOpts{}
			scanOpts.SetDomain(opts.OutName)
			scanOpts.SetScanPath(opts.OutName)
			scanOpts.SetProxy(opts.Proxy)
			scanOpts.SetDryRun(opts.RunDry)
			scanOpts.SetRateLimit(opts.RateLimit)
			scanOpts.SetWordlistPath(opts.WordlistPath)
			scanOpts.SetForceInsecure(opts.UseHttpInsecure)
			scanOpts.SetGobuster(opts.Gobuster)
			scanOpts.SetPortScan(opts.PortScan)
			scanOpts.SetPorts(opts.Ports)
			scanOpts.SetNuclei(opts.Nuclei)

			if opts.TargetFilePath == "" {
				scanOpts.Run()
				return
			}

			scanner := helper.LoadTargetFile(opts.TargetFilePath)
			defer scanner.Close()

			for scanner.Scan() {
				targetDomain := scanner.Text()
				scanOpts.SetDomain(targetDomain)
				scanOpts.Run()
			}
		},
	}

	var osintCmd = &cobra.Command{
		Use:   "osint",
		Short: "Run OSINT tools to retrieve IP addresses and interesting assets",
		Long:  "Runs dorks, subfinder, assetfinder, dnsx & gau to find subdomains, assets & historical URLs",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {

			if opts.OutName == "" && opts.TargetFilePath == "" {
				fmt.Println("[!] Error: target cannot be empty. Please run with --target [something] or --file [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			helper.CheckProxy(opts.Proxy)
			helper.DisplayNetInfo()

			if opts.OutName == "" || !helper.Exists(opts.OutName) {
				fmt.Println("[!] collected assets will be sent to current working directory")
			}

			osintOpts := osint.OsintOpts{}
			osintOpts.SetDomain(opts.OutName)
			osintOpts.SetScanPath(opts.OutName)
			osintOpts.SetProxy(opts.Proxy)
			osintOpts.SetDryRun(opts.RunDry)
			osintOpts.SetRateLimit(opts.RateLimit)
			osintOpts.SetEmailsFile(opts.EmailsFilePath)

			// if used create subcommand, put the results in scans
			if helper.Exists(opts.OutName + "/scans/") {
				osintOpts.SetScanPath(opts.OutName + "/scans")
			}

			if opts.TargetFilePath == "" {
				osintOpts.Run()
				return
			}

			scanner := helper.LoadTargetFile(opts.TargetFilePath)
			defer scanner.Close()

			for scanner.Scan() {
				targetDomain := scanner.Text()
				osintOpts.SetDomain(targetDomain)
				osintOpts.Run()
			}
		},
	}

	var createDirectories = &cobra.Command{
		Use:   "create",
		Short: "Create a work tree to perform scanning, OSINT, and other targets",
		Long:  "Set up a clean-cut architecture at the launch of your assessments",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {

			if opts.OutName == "" {
				fmt.Println("[!] Error: target cannot be empty. Please run with --target [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			if strings.Contains(opts.OutName, ",") {
				directories := strings.Split(opts.OutName, ",")
				for _, d := range directories {
					helper.SetUpDirectoryArchitecture(d)
				}
			} else {
				helper.SetUpDirectoryArchitecture(opts.OutName)
			}

			fmt.Println("[+] Done. Happy hunting :)~")
		},
	}

	defaults := GetDefaultOptions()
	var rootCmd = createDirectories
	rootCmd.Flags().StringVarP(&opts.OutName, "dir-name", "d", defaults.OutName, "Directory name to create (you can also put multiple names and separate them with a ,)")

	rootCmd.AddCommand(osintCmd)
	osintCmd.Flags().StringVarP(&opts.OutName, "dir-name", "d", defaults.OutName, "Outfile directory name (if no target-file is specified, will also be target domain)")
	osintCmd.Flags().StringVarP(&opts.Proxy, "proxy", "p", defaults.Proxy, "Proxy URL (used for the tools supporting it. Other will prompt a warning msg)")
	osintCmd.Flags().BoolVarP(&opts.RunDry, "dry", "", defaults.RunDry, "Run a dry-run (test mode)")
	osintCmd.Flags().Int32VarP(&opts.RateLimit, "rate-limit", "r", defaults.RateLimit, "Requests rate-limit (used for the tools supporting it. Other will prompt a warning msg)")
	osintCmd.Flags().StringVarP(&opts.TargetFilePath, "file", "f", defaults.TargetFilePath, "File containing list of targets (should be a list of IP Addresses or domains)")
	osintCmd.Flags().StringVarP(&opts.EmailsFilePath, "emails", "e", defaults.EmailsFilePath, "File containing list of emails for credential leak checking")

	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&opts.OutName, "dir-name", "d", defaults.OutName, "Outfile directory name (if no target-file is specified, will also be target domain)")
	scanCmd.Flags().StringVarP(&opts.Proxy, "proxy", "p", defaults.Proxy, "Proxy URL (used for the tools supporting it. Other will prompt a warning msg)")
	scanCmd.Flags().BoolVarP(&opts.RunDry, "dry", "", defaults.RunDry, "Run a dry-run (test mode)")
	scanCmd.Flags().BoolVarP(&opts.Gobuster, "gobuster", "", defaults.Gobuster, "Run gobuster directory bruteforce")
	scanCmd.Flags().BoolVarP(&opts.UseHttpInsecure, "insecure", "k", defaults.UseHttpInsecure, "Ignore SSL warnings and force http")
	scanCmd.Flags().Int32VarP(&opts.RateLimit, "rate-limit", "r", defaults.RateLimit, "Requests rate-limit (used for the tools supporting it. Other will prompt a warning msg)")
	scanCmd.Flags().StringVarP(&opts.WordlistPath, "wordlist", "w", defaults.WordlistPath, "Wordlist to use")
	scanCmd.Flags().StringVarP(&opts.TargetFilePath, "file", "f", defaults.TargetFilePath, "File containing list of targets (should be a list of IP Addresses or domains)")
	scanCmd.Flags().BoolVarP(&opts.PortScan, "port-scan", "", defaults.PortScan, "Run TCP port scan and service fingerprinting")
	scanCmd.Flags().StringVarP(&opts.Ports, "ports", "", defaults.Ports, "Ports to scan, comma-separated or ranges (e.g. 22,80,443,8000-9000)")
	scanCmd.Flags().BoolVarP(&opts.Nuclei, "nuclei", "", defaults.Nuclei, "Run nuclei template-based vulnerability scanning (downloads templates on first run)")

	rootCmd.AddCommand(pruneCmd)
	pruneCmd.Flags().StringVarP(&opts.Proxy, "proxy", "p", defaults.Proxy, "Proxy URL (used for the tools supporting it. Other will prompt a warning msg)")
	pruneCmd.Flags().BoolVarP(&opts.UseHttpInsecure, "insecure", "k", defaults.UseHttpInsecure, "Ignore SSL warnings and force http")
	pruneCmd.Flags().StringVarP(&opts.TargetFilePath, "file", "f", defaults.TargetFilePath, "File containing list of targets (should be a list of IP Addresses or domains)")
	pruneCmd.Flags().StringVarP(&opts.OutName, "out", "o", defaults.OutName, "output file path")

	rootCmd.AddCommand(fingerprintCmd)
	fingerprintCmd.Flags().StringVarP(&opts.OutName, "dir-name", "d", defaults.OutName, "Outfile directory name (if no target-file is specified, will also be target domain)")
	fingerprintCmd.Flags().StringVarP(&opts.Proxy, "proxy", "p", defaults.Proxy, "Proxy URL (used for the tools supporting it. Other will prompt a warning msg)")
	fingerprintCmd.Flags().BoolVarP(&opts.UseHttpInsecure, "insecure", "k", defaults.UseHttpInsecure, "Ignore SSL warnings and force http")
	fingerprintCmd.Flags().StringVarP(&opts.TargetFilePath, "file", "f", defaults.TargetFilePath, "File containing list of targets (should be a list of IP Addresses or domains)")

	return rootCmd
}
