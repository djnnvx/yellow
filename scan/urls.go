package scan

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func capURLs(urls []string, max int, who string) []string {
	if max <= 0 || len(urls) <= max {
		return urls
	}
	fmt.Printf("[!] %s: capping %d URLs to %d, %d dropped (raise --katana-max-urls to widen)\n",
		who, len(urls), max, len(urls)-max)
	return urls[:max]
}

// dirRoots reduces crawled URLs to the unique directories worth bruteforcing.
func dirRoots(urls []string) []string {
	seen := map[string]bool{}
	roots := []string{}

	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}

		path := u.Path
		if !strings.HasSuffix(path, "/") {
			path = path[:strings.LastIndex(path, "/")+1]
		}
		if path == "" {
			path = "/"
		}

		root := u.Scheme + "://" + u.Host + path
		if !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}

	sort.Strings(roots)
	return roots
}
