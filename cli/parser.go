package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"evil.djnn.sh/djnn/yellow/helpers"
	"evil.djnn.sh/djnn/yellow/osint"
	"evil.djnn.sh/djnn/yellow/scan"
)

func GetParser(opts *StandardOptions) *cobra.Command {

	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Run active scanning tools to perform enumeration",
		Long:  "Runs active scanning (naabu, katana, wappalyzergo, sitemap, robots.txt, gobuster, nuclei, httpx, gowitness)",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {

			if opts.OutDirName == "" && opts.TargetFilePath == "" {
				fmt.Println("[!] Error: target cannot be empty. Please run with --target [something] or --file [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			helper.CheckProxy(opts.Proxy)
			helper.DisplayNetInfo()

			if opts.OutDirName == "" || !helper.Exists(opts.OutDirName) {
				println("[!] collected assets will be sent to current working directory")
			}

			scanOpts := scan.ScanOpts{}
			scanOpts.SetDomain(opts.OutDirName)
			scanOpts.SetScanPath(opts.OutDirName)
			scanOpts.SetProxy(opts.Proxy)
			scanOpts.SetDryRun(opts.RunDry)
			scanOpts.SetRateLimit(opts.RateLimit)
			scanOpts.SetWordlistPath(opts.WordlistPath)
			scanOpts.SetForceInsecure(opts.UseHttpInsecure)
			scanOpts.SetWithPortScan(opts.WithPortScan)

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
		Long:  "Runs dorks, subfinder, assetfinder & dnsx on all domains to find subdomains & assets",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {

			if opts.OutDirName == "" && opts.TargetFilePath == "" {
				fmt.Println("[!] Error: target cannot be empty. Please run with --target [something] or --file [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			helper.CheckProxy(opts.Proxy)
			helper.DisplayNetInfo()

			if opts.OutDirName == "" || !helper.Exists(opts.OutDirName) {
				println("[!] collected assets will be sent to current working directory")
			}

			osintOpts := osint.OsintOpts{}
			osintOpts.SetDomain(opts.OutDirName)
			osintOpts.SetScanPath(opts.OutDirName)
			osintOpts.SetProxy(opts.Proxy)
			osintOpts.SetDryRun(opts.RunDry)
			osintOpts.SetRateLimit(opts.RateLimit)

			// if used create subcommand, put the results in scans
			if helper.Exists(opts.OutDirName + "/scans/") {
				osintOpts.SetScanPath(opts.OutDirName + "/scans")
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

			if opts.OutDirName == "" {
				fmt.Println("[!] Error: target cannot be empty. Please run with --target [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			if strings.Contains(opts.OutDirName, ",") {
				directories := strings.Split(opts.OutDirName, ",")
				for _, d := range directories {
					helper.SetUpDirectoryArchitecture(d)
				}
			} else {
				helper.SetUpDirectoryArchitecture(opts.OutDirName)
			}

			fmt.Println("[+] Done. Happy hunting :)~")
		},
	}

	defaults := GetDefaultOptions()
	var rootCmd = createDirectories
	rootCmd.Flags().StringVarP(&opts.OutDirName, "dir-name", "d", defaults.OutDirName, "Directory name to create (you can also put multiple names and separate them with a ,)")

	rootCmd.AddCommand(osintCmd)
	osintCmd.Flags().StringVarP(&opts.OutDirName, "dir-name", "d", defaults.OutDirName, "Outfile directory name (if no target-file is specified, will also be target domain)")
	osintCmd.Flags().StringVarP(&opts.Proxy, "proxy", "p", defaults.Proxy, "Proxy URL (used for the tools supporting it. Other will prompt a warning msg)")
	osintCmd.Flags().BoolVarP(&opts.RunDry, "dry", "", defaults.RunDry, "Run a dry-run (test mode)")
	osintCmd.Flags().Int32VarP(&opts.RateLimit, "rate-limit", "r", defaults.RateLimit, "Requests rate-limit (used for the tools supporting it. Other will prompt a warning msg)")
	osintCmd.Flags().StringVarP(&opts.TargetFilePath, "file", "f", defaults.TargetFilePath, "File containing list of targets (should be a list of IP Addresses or domains)")

	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&opts.OutDirName, "dir-name", "d", defaults.OutDirName, "Outfile directory name (if no target-file is specified, will also be target domain)")
	scanCmd.Flags().StringVarP(&opts.Proxy, "proxy", "p", defaults.Proxy, "Proxy URL (used for the tools supporting it. Other will prompt a warning msg)")
	scanCmd.Flags().BoolVarP(&opts.RunDry, "dry", "", defaults.RunDry, "Run a dry-run (test mode)")
	scanCmd.Flags().BoolVarP(&opts.UseHttpInsecure, "with-port-scanning", "", defaults.WithPortScan, "enable port-scanning")
	scanCmd.Flags().BoolVarP(&opts.UseHttpInsecure, "insecure", "k", defaults.UseHttpInsecure, "Ignore SSL warnings and force http")
	scanCmd.Flags().Int32VarP(&opts.RateLimit, "rate-limit", "r", defaults.RateLimit, "Requests rate-limit (used for the tools supporting it. Other will prompt a warning msg)")
	scanCmd.Flags().StringVarP(&opts.WordlistPath, "wordlist", "w", defaults.WordlistPath, "Wordlist to use")
	scanCmd.Flags().StringVarP(&opts.TargetFilePath, "file", "f", defaults.TargetFilePath, "File containing list of targets (should be a list of IP Addresses or domains)")

	return rootCmd
}
