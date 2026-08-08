package scan

import (
	"testing"

	"github.com/projectdiscovery/katana/pkg/utils/scope"
)

func TestInScope(t *testing.T) {
	scoper, err := scope.NewManager(nil, nil, katanaFieldScope, false)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]bool{
		"https://djnn.sh/":                            true,
		"https://evil.djnn.sh/a/b":                    true,
		"https://services.djnn.sh/x":                  true,
		"https://github.com/djnnvx":                   false,
		"https://cdnjs.cloudflare.com/ajax/libs/x.js": false,
		"https://www.youtube.com/watch?v=1":           false,
		"::::not a url":                               false,
	}

	for raw, want := range cases {
		if got := inScope(scoper, raw, "djnn.sh"); got != want {
			t.Errorf("%s: got %v, want %v", raw, got, want)
		}
	}
}
