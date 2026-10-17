// SPDX-License-Identifier: Apache-2.0

package domain

import "testing"

func TestMatches(t *testing.T) {
	cases := []struct {
		url  string
		pats []string
		want bool
	}{
		{"https://example.com/a", []string{"example.com"}, true},
		{"https://EXAMPLE.com./a", []string{"example.com"}, true},
		{"https://a.example.com/", []string{"*.example.com"}, true},
		{"https://example.com/", []string{"*.example.com"}, false},
		{"https://badexample.com/", []string{"*.example.com"}, false},
		{"https://user@example.com/", []string{"example.com"}, false},
		{"ftp://example.com/", []string{"example.com"}, false},
		{"example.com", []string{"example.com"}, true},
		{"example.com/path", []string{"example.com"}, false},
	}
	for _, c := range cases {
		if got := Matches(c.url, c.pats); got != c.want {
			t.Errorf("Matches(%q, %v) = %v", c.url, c.pats, got)
		}
	}
}

func TestSites(t *testing.T) {
	allow := Sites{Domains: []string{"*.example.com"}}
	block := Sites{Blocklist: true, Domains: []string{"*.example.com"}}
	cases := []struct {
		s    Sites
		url  string
		want bool
	}{
		{allow, "https://a.example.com/", true},
		{allow, "https://ozon.ru/", false},
		{Sites{}, "https://ozon.ru/", false},
		{block, "https://ozon.ru/", true},
		{block, "https://a.example.com/", false},
		{Sites{Blocklist: true}, "https://ozon.ru/", true},
		{block, "ftp://ozon.ru/", false},
		{block, "http://localhost:8080/", false},
		{block, "http://127.0.0.1/", false},
		{block, "http://192.168.1.1/", false},
		{block, "http://[::1]/", false},
		{block, "http://169.254.169.254/", false},
		{Sites{Domains: []string{"localhost"}}, "http://localhost:8080/", true},
	}
	for _, c := range cases {
		if got := c.s.Allows(c.url); got != c.want {
			t.Errorf("%+v.Allows(%q) = %v", c.s, c.url, got)
		}
	}
}
