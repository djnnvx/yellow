package scan

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestMatchLocation(t *testing.T) {
	cases := []struct {
		name  string
		event output.ResultEvent
		want  string
	}{
		{"prefers matched", output.ResultEvent{Matched: "https://x.tld/a", URL: "https://x.tld", Host: "x.tld"}, "https://x.tld/a"},
		{"falls back to url", output.ResultEvent{URL: "https://x.tld", Host: "x.tld"}, "https://x.tld"},
		{"falls back to host", output.ResultEvent{Host: "x.tld"}, "x.tld"},
		{"never empty", output.ResultEvent{}, "unknown"},
	}

	for _, c := range cases {
		if got := matchLocation(&c.event); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// The exact shape nuclei emits once its host-error cache gives up on a target.
// Recording these as findings is what turned one rate-limited host into 95913
// "findings", 16283 of them critical, on a static site.
func TestFindingSetRejectsNonMatches(t *testing.T) {
	s := newFindingSet()

	skipped := &output.ResultEvent{
		TemplateID:    "dbgate-anonymous-access",
		Host:          "https://evil.djnn.sh",
		MatcherStatus: false,
		Error:         "host was skipped as it was found unresponsive",
	}
	if f, _ := s.add(skipped); f != nil {
		t.Error("skipped-host event must not become a finding")
	}
	if f, _ := s.add(nil); f != nil {
		t.Error("nil event must not become a finding")
	}
	if f, _ := s.add(&output.ResultEvent{TemplateID: "x", Matched: "https://x.tld/a"}); f != nil {
		t.Error("MatcherStatus false must not become a finding")
	}

	if s.hits() != 0 || len(s.sorted()) != 0 {
		t.Errorf("set must stay empty, got %d hit(s) in %d group(s)", s.hits(), len(s.sorted()))
	}

	real := &output.ResultEvent{TemplateID: "x", Matched: "https://x.tld/a", MatcherStatus: true}
	if f, isNew := s.add(real); f == nil || !isNew {
		t.Error("a real match must be recorded")
	}
}

func TestFindingSetGroups(t *testing.T) {
	event := func(id, matched string) *output.ResultEvent {
		return &output.ResultEvent{TemplateID: id, Matched: matched, MatcherStatus: true}
	}

	s := newFindingSet()
	if _, isNew := s.add(event("wp-optimize", "https://evil.tld/a")); !isNew {
		t.Error("first hit must open a new group")
	}
	if _, isNew := s.add(event("wp-optimize", "https://evil.tld/b")); isNew {
		t.Error("same template on same host must join the existing group")
	}
	s.add(event("wp-optimize", "https://evil.tld/c"))
	s.add(event("wp-optimize", "https://other.tld/a"))
	s.add(event("aem-bypass", "https://evil.tld/a"))

	if s.hits() != 5 {
		t.Errorf("hits: got %d, want 5", s.hits())
	}

	got := s.sorted()
	if len(got) != 3 {
		t.Fatalf("groups: got %d, want 3", len(got))
	}
	if got[0].Host != "evil.tld" || got[0].TemplateID != "wp-optimize" || len(got[0].Matched) != 3 {
		t.Errorf("noisiest group first: got %+v", got[0])
	}
	if len(got[1].Matched) != 1 || len(got[2].Matched) != 1 {
		t.Errorf("tail groups should hold one hit each: got %+v, %+v", got[1], got[2])
	}
}

func TestFindingSetConcurrent(t *testing.T) {
	s := newFindingSet()
	done := make(chan struct{})

	for i := range 8 {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := range 50 {
				s.add(&output.ResultEvent{
					TemplateID:    "tpl",
					Matched:       fmt.Sprintf("https://x.tld/%d-%d", i, j),
					MatcherStatus: true,
				})
			}
		}(i)
	}
	for range 8 {
		<-done
	}

	if s.hits() != 400 {
		t.Errorf("hits: got %d, want 400", s.hits())
	}
	if got := s.sorted(); len(got) != 1 {
		t.Errorf("all hits share template+host, want 1 group, got %d", len(got))
	}
}
