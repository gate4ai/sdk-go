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
