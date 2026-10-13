// SPDX-License-Identifier: Apache-2.0

// Package domain — сопоставление адресов с шаблонами доменов: одно правило для
// политик хоста, возможностей коннекторов и самих коннекторов.
package domain

import (
	"net/url"
	"strings"
)

// HostOf — хост http(s)-URL или голого имени хоста в нижнем регистре; "" — если
// это не http(s), есть userinfo или строка не разбирается.
func HostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		if strings.ContainsAny(raw, "/?#@:") {
			return ""
		}
		return strings.TrimSuffix(strings.ToLower(raw), ".")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

// HostMatches — хост совпадает с шаблоном: "example.com" — точно,
// "*.example.com" — только поддомены (не сам example.com).
func HostMatches(host, pattern string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	p := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	if host == "" || p == "" {
		return false
	}
	if strings.HasPrefix(p, "*.") {
		return strings.HasSuffix(host, p[1:]) && len(host) > len(p)-1
	}
	return host == p
}

// Matches — хост URL совпадает с одним из шаблонов.
func Matches(raw string, patterns []string) bool {
	h := HostOf(raw)
	if h == "" {
		return false
	}
	for _, p := range patterns {
		if HostMatches(h, p) {
			return true
		}
	}
	return false
}
