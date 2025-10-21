package helper

import (
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
