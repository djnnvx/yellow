package scan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"evil.djnn.sh/djnn/yellow/core"
	helper "evil.djnn.sh/djnn/yellow/helpers"
)

// Fabricated, non-functional credentials, assembled at runtime so no
// secret-shaped literal sits in the source and trips push protection.
// AWS key ids are base32, hence the restricted charset there.
const (
	charsAlnum  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsDigits = "0123456789"
	charsBase32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

func mkFake(prefix, charset string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[(i*7+3)%len(charset)]
	}
	return prefix + string(b)
}

var (
	fakeSlackToken = mkFake("xoxb-", charsDigits, 12) + "-" + mkFake("", charsDigits, 13)
	fakeGithubPAT  = mkFake("ghp_", charsAlnum, 36)
	fakeAWSKeyID   = mkFake("AKIA", charsBase32, 16)
	malformedAWSID = mkFake("AKIA", charsBase32, 15) + "9" // 9 is not base32
)

func TestShouldScanBody(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"application/javascript", true},
		{"text/javascript; charset=utf-8", true},
		{"application/json", true},
		{"text/html; charset=utf-8", true},
		{"text/css", true},
		{"application/xml", true},
		{"text/plain", true},
		{"image/png", false},
		{"font/woff2", false},
		{"video/mp4", false},
		{"application/octet-stream", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := shouldScanBody(tt.ct); got != tt.want {
			t.Errorf("shouldScanBody(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}

func TestFetchScannableSkipsBinary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("token = \"" + fakeSlackToken + "\""))
	}))
	defer srv.Close()

	if _, ok := fetchScannable(helper.GetHttpClient(true), srv.URL); ok {
		t.Error("binary content-type must not be fetched for scanning")
	}
}

func TestSecretsDetectsPlantedCredentials(t *testing.T) {
	body := "var cfg={\n  slack:\"" + fakeSlackToken + "\",\n" +
		"  github:\"" + fakeGithubPAT + "\",\n" +
		"  awsKeyId:\"" + fakeAWSKeyID + "\"\n};\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	dir := t.TempDir()
	ctx := &core.Context{Domain: srv.URL, ScanPath: dir, URLs: []string{srv.URL + "/app.js"}}

	if err := (&Secrets{MaxURLs: 10}).Run(ctx); err != nil {
		t.Fatalf("Run returned %v", err)
	}

	byRule := map[string]SecretFinding{}
	for _, f := range readSecrets(t, dir) {
		byRule[f.RuleID] = f
	}

	want := map[string]string{
		"slack-bot-token":  fakeSlackToken,
		"github-pat":       fakeGithubPAT,
		"aws-access-token": fakeAWSKeyID,
	}
	for rule, secret := range want {
		got, ok := byRule[rule]
		if !ok {
			t.Errorf("rule %s did not fire; got rules %v", rule, keysOf(byRule))
			continue
		}
		if got.Secret != secret {
			t.Errorf("%s: secret = %q, want %q", rule, got.Secret, secret)
		}
		if got.URL != srv.URL+"/app.js" {
			t.Errorf("%s: url = %q, want the source URL", rule, got.URL)
		}
	}
}

// a key id with a char outside base32 is not a real AWS key and must not match
func TestSecretsIgnoresMalformedAWSKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("var k=\"" + malformedAWSID + "\";\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	ctx := &core.Context{Domain: srv.URL, ScanPath: dir, URLs: []string{srv.URL + "/bad.js"}}

	if err := (&Secrets{MaxURLs: 10}).Run(ctx); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	for _, f := range readSecrets(t, dir) {
		if f.RuleID == "aws-access-token" {
			t.Errorf("matched a non-base32 key id: %q", f.Secret)
		}
	}
}

func keysOf(m map[string]SecretFinding) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSecretsDedupesSameSecretAcrossURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("var t=\"" + fakeGithubPAT + "\";\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	ctx := &core.Context{
		Domain:   srv.URL,
		ScanPath: dir,
		URLs:     []string{srv.URL + "/a.js", srv.URL + "/b.js", srv.URL + "/c.js"},
	}

	if err := (&Secrets{MaxURLs: 10}).Run(ctx); err != nil {
		t.Fatalf("Run returned %v", err)
	}

	findings := readSecrets(t, dir)
	if len(findings) != 1 {
		t.Errorf("same secret on 3 URLs produced %d records, want 1 deduped", len(findings))
	}
}

func TestSecretsCleanBodyYieldsNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("function add(a,b){return a+b}\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	ctx := &core.Context{Domain: srv.URL, ScanPath: dir, URLs: []string{srv.URL + "/clean.js"}}

	if err := (&Secrets{MaxURLs: 10}).Run(ctx); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if findings := readSecrets(t, dir); len(findings) != 0 {
		t.Errorf("clean body produced %d findings: %+v", len(findings), findings)
	}
}

func readSecrets(t *testing.T, dir string) []SecretFinding {
	t.Helper()
	data, err := os.ReadFile(dir + "/secrets.json")
	if err != nil {
		t.Fatalf("secrets.json not written: %v", err)
	}
	var findings []SecretFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("secrets.json is not valid json: %v", err)
	}
	return findings
}
