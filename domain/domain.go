// SPDX-License-Identifier: Apache-2.0

// Package domain — сопоставление адресов с шаблонами доменов: одно правило для
// политик хоста, возможностей коннекторов и самих коннекторов.
package domain

import (
	"net"
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

// Sites — какие сайты разрешены: белый список (только Domains) или чёрный
// (все, кроме Domains).
type Sites struct {
	Blocklist bool
	Domains   []string
}

// Allows — URL разрешён. Не http(s)-адрес не разрешён ни в каком режиме;
// чёрный список не открывает адреса этой машины и локальной сети (localhost,
// IP loopback, частные и link-local) — их можно разрешить только белым списком.
func (s Sites) Allows(raw string) bool {
	h := HostOf(raw)
	if h == "" {
		return false
	}
	if !s.Blocklist {
		return Matches(raw, s.Domains)
	}
	return !isLocal(h) && !Matches(raw, s.Domains)
}

func isLocal(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}
