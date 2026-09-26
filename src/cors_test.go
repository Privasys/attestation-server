package main

import "testing"

func TestOriginAllowed(t *testing.T) {
	for origin, want := range map[string]bool{
		"https://developer.privasys.org": true,
		"https://harness.covextra.com":   true,
		"https://privasys.id":            true,
		"http://localhost:4210":          true,
		"http://127.0.0.1":               true,
		"http://harness.covextra.com":    false,
		"null":                           false,
		"":                               false,
		"file://":                        false,
	} {
		if got := originAllowed(origin); got != want {
			t.Errorf("originAllowed(%q) = %v, want %v", origin, got, want)
		}
	}
}
