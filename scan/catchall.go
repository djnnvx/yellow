package scan

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	helper "evil.djnn.sh/djnn/yellow/helpers"
)

// answersEveryPath probes a path that cannot exist. A host that still answers
// makes every path-existence template match, so its findings are worthless.
func answersEveryPath(root string) bool {
	probe := root + "/yellow-probe-" + strconv.FormatInt(time.Now().UnixNano(), 36)

	req, err := http.NewRequest("GET", probe, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", helper.GetUserAgent())

	resp, err := helper.GetHttpClient(true).Do(req)
	if err != nil || resp == nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < http.StatusBadRequest
}

// collapseCatchAll replaces each catch-all host's URLs with just its root, so
// one bogus finding is reported instead of one per crawled URL.
func collapseCatchAll(urls []string, catchAll func(string) bool) []string {
	probed := map[string]bool{}
	kept := map[string]bool{}
	out := []string{}

	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			out = append(out, raw)
			continue
		}

		root := u.Scheme + "://" + u.Host
		bad, seen := probed[root]
		if !seen {
			bad = catchAll(root)
			probed[root] = bad
			if bad {
				fmt.Printf("[!] nuclei: %s answers every path, collapsing to 1 target (findings here may be false positives)\n", root)
			}
		}

		if !bad {
			out = append(out, raw)
			continue
		}
		if !kept[root] {
			kept[root] = true
			out = append(out, root+"/")
		}
	}

	return out
}
