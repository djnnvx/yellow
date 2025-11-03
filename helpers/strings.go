package helper

import (
	"encoding/json"
	"strings"
	"unicode"
)

func ReplaceWithHyphen(input string) string {
	var result strings.Builder
	for _, r := range input {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' {
			result.WriteRune(r)
		} else {
			result.WriteRune('-')
		}
	}

	return result.String()
}

// if its not a valid domain in the end, not too big of a deal,
// we just want an approximate response
func StringHasUnwantedCharactersForDomainName(url string) bool {
	badChars := ":;\t\n, +\\\"[]{}()="
	for _, b := range badChars {
		if strings.Contains(url, string(b)) {
			return true
		}
	}

	if strings.HasSuffix(url, ".") {
		return true
	}

	if strings.HasPrefix(url, "Name") {
		return true
	}

	return false
}

func ExtractString(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func ExtractInt(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		switch t := v.(type) {
		case json.Number:
			if i, err := t.Int64(); err == nil {
				return int(i)
			}
			if f, err := t.Float64(); err == nil {
				return int(f)
			}
		case float64:
			return int(t)
		case int:
			return t
		case int64:
			return int(t)
		}
	}
	return 0
}

func ExtractNumberAsFloat(m map[string]any, k string) (float64, bool) {
	if v, ok := m[k]; ok {
		switch t := v.(type) {
		case json.Number:
			f, err := t.Float64()
			if err != nil {
				return 0, false
			}
			return f, true
		case float64:
			return t, true
		}
	}
	return 0, false
}
