package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	helpers "evil.djnn.sh/djnn/yellow/helpers"
)

func GetParser(opts *StandardOptions) *cobra.Command {

	var osintCmd = &cobra.Command{
		Use:   "osint",
		Short: "Run OSINT tools to retrieve IP addresses and interesting assets",
		Long:  "Runs subfinder & dnsx on all domains to find subdomains which are passed to httpx. Also runs google dorks.",
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {

			if opts.OutDirName == "" && opts.TargetFilePath == "" {
				fmt.Println("[!] Error: target cannot be empty. Please run with --target [something] or --file [something]")
				fmt.Println("\nIf you're confused, feel free to use --help option. :)~")
				os.Exit(1)
			}

			helpers.CheckProxy(opts.Proxy)
			helpers.DisplayNetInfo()

			if opts.OutDirName == "" || !helpers.Exists(opts.OutDirName) {
				println("[!] collected assets will be sent to current working directory")
			}

			/*
				createOutDirectory()
				checkProxy()
				displayNetInfo()

				if targetPath == "" {
					scanDomain(domain)
					return
				}

				scanner := loadTargetFile()
				defer scanner.Close()

				for scanner.Scan() {
					targetDomain := scanner.Text()
					scanDomain(targetDomain)
				}
			*/

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

			dirname := helpers.ReplaceWithHyphen(opts.OutDirName)
			fmt.Println("[+] setting up directory architecture for", dirname)

			_ = os.MkdirAll(dirname, 0775)
			helpers.CreateDirectory(dirname, []helpers.Folder{
				{
					Name:     "scans",
					Children: helpers.FolderNameFactory("nmap", "infra", "web", "ssl", "screenshots", "nessus"),
				},
				{
					Name:     "extracted",
					Children: helpers.FolderNameFactory("assets", "creds", "code"),
				},
				{
					Name:     "www",
					Children: helpers.FolderNameFactory("exploits", "tools"),
				},
			})

			fmt.Println("[+] Done. Happy hunting :)~")
		},
	}

	defaults := GetDefaultOptions()
	var rootCmd = createDirectories
	rootCmd.Flags().StringVarP(&opts.OutDirName, "dir-name", "d", defaults.OutDirName, "Pentest target, will be the name of the directories created, for instance")

	rootCmd.AddCommand(osintCmd)
	osintCmd.Flags().StringVarP(&opts.OutDirName, "dir-name", "d", defaults.OutDirName, "Pentest target, will be the name of the directories created, for instance")
	osintCmd.Flags().StringVarP(&opts.Proxy, "proxy", "p", defaults.Proxy, "Proxy URL (used for the tools supporting it. Other will prompt a warning msg)")
	osintCmd.Flags().BoolVarP(&opts.RunDry, "dry", "", defaults.RunDry, "Run a dry-run (test mode)")
	osintCmd.Flags().BoolVarP(&opts.UseHttpInsecure, "insecure", "k", defaults.UseHttpInsecure, "Ignore SSL warnings and force http")
	osintCmd.Flags().Int32VarP(&opts.RateLimit, "rate-limit", "r", defaults.RateLimit, "Requests rate-limit (used for the tools supporting it. Other will prompt a warning msg)")
	osintCmd.Flags().StringVarP(&opts.WordlistPath, "wordlist", "w", defaults.WordlistPath, "Wordlist to use (if any)")
	osintCmd.Flags().StringVarP(&opts.TargetFilePath, "file", "f", defaults.TargetFilePath, "File containing list of targets (should be a list of IP Addresses or domains)")

	return rootCmd
}
