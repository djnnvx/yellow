package scan

import (
	"reflect"
	"testing"
)

func TestDirRoots(t *testing.T) {
	got := dirRoots([]string{
		"https://x.tld/app/login",
		"https://x.tld/app/logout",
		"https://x.tld/app/",
		"https://x.tld/",
		"https://x.tld/api/v1/users?id=1",
		"https://other.tld/a/b/c",
		"::::not a url",
		"/relative/only",
	})

	want := []string{
		"https://other.tld/a/b/",
		"https://x.tld/",
		"https://x.tld/api/v1/",
		"https://x.tld/app/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDirRootsDedupes(t *testing.T) {
	got := dirRoots([]string{
		"https://x.tld/a/1", "https://x.tld/a/2", "https://x.tld/a/3",
	})
	if len(got) != 1 || got[0] != "https://x.tld/a/" {
		t.Errorf("got %v, want one root https://x.tld/a/", got)
	}
}

func TestCapURLs(t *testing.T) {
	five := []string{"a", "b", "c", "d", "e"}

	if got := capURLs(five, 3, "test"); len(got) != 3 {
		t.Errorf("cap 3: got %d entries, want 3", len(got))
	}
	if got := capURLs(five, 10, "test"); len(got) != 5 {
		t.Errorf("cap above length must not truncate: got %d, want 5", len(got))
	}
	if got := capURLs(five, 0, "test"); len(got) != 5 {
		t.Errorf("cap 0 means unlimited: got %d, want 5", len(got))
	}
}
