package scan

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"evil.djnn.sh/djnn/yellow/core"
)

const robotsBody = "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"

func TestRobotsTxtSavesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(robotsBody))
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := (&RobotsTxt{}).Run(&core.Context{Domain: srv.URL, ScanPath: dir}); err != nil {
		t.Fatalf("Run returned %v", err)
	}

	got, err := os.ReadFile(dir + "/robots.txt")
	if err != nil {
		t.Fatalf("robots.txt not written: %v", err)
	}
	if string(got) != robotsBody {
		t.Errorf("got %q, want %q", got, robotsBody)
	}
}

func TestRobotsTxt404WritesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := (&RobotsTxt{}).Run(&core.Context{Domain: srv.URL, ScanPath: dir}); err != nil {
		t.Fatalf("Run returned %v", err)
	}

	if _, err := os.Stat(dir + "/robots.txt"); !os.IsNotExist(err) {
		t.Error("404 left a robots.txt behind")
	}
}

func TestSitemapSavesBody(t *testing.T) {
	const body = `<?xml version="1.0"?><urlset><url><loc>https://x/a</loc></url></urlset>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := (&Sitemap{}).Run(&core.Context{Domain: srv.URL, ScanPath: dir}); err != nil {
		t.Fatalf("Run returned %v", err)
	}

	got, err := os.ReadFile(dir + "/sitemap.xml")
	if err != nil {
		t.Fatalf("sitemap.xml not written: %v", err)
	}
	if string(got) != body {
		t.Errorf("got %q, want %q", got, body)
	}
}
