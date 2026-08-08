package scan

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestAnswersEveryPath(t *testing.T) {
	loginWall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Write([]byte("sign in"))
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer loginWall.Close()

	sane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer sane.Close()

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	if !answersEveryPath(loginWall.URL) {
		t.Error("host redirecting everything to a login page must be flagged")
	}
	if answersEveryPath(sane.URL) {
		t.Error("host returning 404 on unknown paths must not be flagged")
	}
	if answersEveryPath(deadURL) {
		t.Error("unreachable host must fail open, not be flagged")
	}
}

func TestCollapseCatchAll(t *testing.T) {
	probes := map[string]int{}
	catchAll := func(root string) bool {
		probes[root]++
		return root == "https://wall.tld"
	}

	got := collapseCatchAll([]string{
		"https://wall.tld/a",
		"https://ok.tld/1",
		"https://wall.tld/b",
		"https://wall.tld/c",
		"https://ok.tld/2",
		"::::not a url",
	}, catchAll)

	want := []string{
		"https://wall.tld/",
		"https://ok.tld/1",
		"https://ok.tld/2",
		"::::not a url",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if probes["https://wall.tld"] != 1 || probes["https://ok.tld"] != 1 {
		t.Errorf("each host must be probed once, got %v", probes)
	}
}
