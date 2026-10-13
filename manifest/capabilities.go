// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Capabilities — возможности коннектора. Всё, что не объявлено, недоступно:
// функция хоста вернёт capability_denied. Значения могут ссылаться на настройки
// коннектора шаблоном ${setting:путь} (путь через точку: imap.host); список
// в настройке раскрывается в несколько записей, пустое значение запись убирает.
type Capabilities struct {
	Network []NetworkCap `json:"network,omitempty" yaml:"network,omitempty"`
	Secrets []SecretCap  `json:"secrets,omitempty" yaml:"secrets,omitempty"`
	Browser *BrowserCap  `json:"browser,omitempty" yaml:"browser,omitempty"`
	Files   []string     `json:"files,omitempty" yaml:"files,omitempty"` // "<папка>/**" — дерево, иначе один файл
	Storage *StorageCap  `json:"storage,omitempty" yaml:"storage,omitempty"`
	Events  []string     `json:"events,omitempty" yaml:"events,omitempty"` // подписки на события (целевое)
}

// Схемы сетевых возможностей.
const (
	SchemeHTTPS = "https" // http_request
	SchemeHTTP  = "http"  // http_request (только loopback)
	SchemeTLS   = "tls"   // tls_dial с tls / starttls
	SchemeTCP   = "tcp"   // tls_dial без TLS (только loopback)
)

// NetworkCap — разрешённый адрес. Port пустой — любой порт.
type NetworkCap struct {
	Host   string `json:"host" yaml:"host"`
	Port   string `json:"port,omitempty" yaml:"port,omitempty"`
	Scheme string `json:"scheme" yaml:"scheme"`
}

// SecretCap — секрет по алиасу Vault и адреса, для которых хост его подставляет.
type SecretCap struct {
	Alias string   `json:"alias" yaml:"alias"`
	Bind  []string `json:"bind" yaml:"bind"`
}

// BrowserCap — домены для функций browser_*.
type BrowserCap struct {
	Domains []string `json:"domains" yaml:"domains"`
}

// StorageCap — собственное KV-хранилище коннектора.
type StorageCap struct {
	QuotaMB int `json:"quota_mb" yaml:"quota_mb"`
}

// Limits — лимиты одного вызова.
type Limits struct {
	MemoryMB        int `json:"memory_mb,omitempty" yaml:"memory_mb,omitempty"`
	TimeoutS        int `json:"timeout_s,omitempty" yaml:"timeout_s,omitempty"`
	VerifyDeadlineS int `json:"verify_deadline_s,omitempty" yaml:"verify_deadline_s,omitempty"`
}

// Значения лимитов по умолчанию.
const (
	DefaultMemoryMB        = 128
	DefaultTimeoutS        = 60
	DefaultVerifyDeadlineS = 86400
)

// WithDefaults — лимиты с подставленными значениями по умолчанию.
func (l Limits) WithDefaults() Limits {
	if l.MemoryMB == 0 {
		l.MemoryMB = DefaultMemoryMB
	}
	if l.TimeoutS == 0 {
		l.TimeoutS = DefaultTimeoutS
	}
	if l.VerifyDeadlineS == 0 {
		l.VerifyDeadlineS = DefaultVerifyDeadlineS
	}
	return l
}

var tmplRe = regexp.MustCompile(`\$\{setting:([a-zA-Z0-9_.]+)\}`)

func checkTemplate(field, v string) error {
	if strings.Contains(strings.ReplaceAll(v, "${setting:", ""), "${") {
		return fmt.Errorf("%s: bad template in %q", field, v)
	}
	if n := len(tmplRe.FindAllString(v, -1)); n > 1 {
		return fmt.Errorf("%s: only one ${setting:…} per value (%q)", field, v)
	}
	return nil
}

func (c Capabilities) validate() error {
	for _, n := range c.Network {
		switch n.Scheme {
		case SchemeHTTPS, SchemeHTTP, SchemeTLS, SchemeTCP:
		default:
			return fmt.Errorf("capabilities.network: bad scheme %q", n.Scheme)
		}
		if n.Host == "" {
			return errors.New("capabilities.network: empty host")
		}
		if err := checkTemplate("capabilities.network.host", n.Host); err != nil {
			return err
		}
		if err := checkTemplate("capabilities.network.port", n.Port); err != nil {
			return err
		}
		if n.Port != "" && !tmplRe.MatchString(n.Port) {
			if p, err := strconv.Atoi(n.Port); err != nil || p <= 0 || p > 65535 {
				return fmt.Errorf("capabilities.network: bad port %q", n.Port)
			}
		}
	}
	for _, s := range c.Secrets {
		if !strings.HasPrefix(s.Alias, "@") && !tmplRe.MatchString(s.Alias) {
			return fmt.Errorf("capabilities.secrets: alias %q must start with @ or be ${setting:…}", s.Alias)
		}
		if len(s.Bind) == 0 {
			return fmt.Errorf("capabilities.secrets: %s: empty bind (a secret must be bound to addresses)", s.Alias)
		}
		for _, b := range append([]string{s.Alias}, s.Bind...) {
			if err := checkTemplate("capabilities.secrets", b); err != nil {
				return err
			}
		}
	}
	if c.Browser != nil {
		for _, d := range c.Browser.Domains {
			if err := checkTemplate("capabilities.browser.domains", d); err != nil {
				return err
			}
		}
	}
	for _, f := range c.Files {
		if err := checkTemplate("capabilities.files", f); err != nil {
			return err
		}
		if !strings.HasPrefix(f, "/") && !strings.HasPrefix(f, "~") && !strings.HasPrefix(f, "${setting:") {
			return fmt.Errorf("capabilities.files: %q must be absolute, ~/… or ${setting:…}", f)
		}
	}
	if c.Storage != nil && c.Storage.QuotaMB <= 0 {
		return errors.New("capabilities.storage.quota_mb must be positive")
	}
	return nil
}

// Resolved — возможности с подставленными настройками конкретного экземпляра.
type Resolved struct {
	Network        []NetworkRule
	Secrets        []SecretRule
	BrowserDomains []string
	Browser        bool
	Files          []string
	StorageBytes   int64
}

// NetworkRule — разрешённый адрес; Port 0 — любой.
type NetworkRule struct {
	Host   string
	Port   int
	Scheme string
}

// SecretRule — алиас и адреса привязки.
type SecretRule struct {
	Alias string
	Bind  []string
}

// lookup — значение настройки по пути через точку.
func lookup(settings map[string]any, path string) any {
	var cur any = settings
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func scalars(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, scalars(x)...)
		}
		return out
	case []string:
		var out []string
		for _, x := range t {
			out = append(out, scalars(x)...)
		}
		return out
	case float64:
		return []string{strconv.FormatFloat(t, 'f', -1, 64)}
	case int:
		return []string{strconv.Itoa(t)}
	case bool:
		return []string{strconv.FormatBool(t)}
	}
	return []string{fmt.Sprint(v)}
}

// Expand раскрывает шаблон ${setting:…} по настройкам: ноль, одно или несколько значений.
func Expand(v string, settings map[string]any) []string {
	m := tmplRe.FindStringSubmatchIndex(v)
	if m == nil {
		if v == "" {
			return nil
		}
		return []string{v}
	}
	var out []string
	for _, x := range scalars(lookup(settings, v[m[2]:m[3]])) {
		out = append(out, v[:m[0]]+x+v[m[1]:])
	}
	return out
}

func expandAll(vs []string, settings map[string]any) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range vs {
		for _, x := range Expand(v, settings) {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// Resolve подставляет настройки экземпляра в возможности.
func (c Capabilities) Resolve(settings map[string]any) (Resolved, error) {
	var r Resolved
	for _, n := range c.Network {
		ports := []int{0}
		if n.Port != "" {
			ports = nil
			for _, p := range Expand(n.Port, settings) {
				v, err := strconv.Atoi(p)
				if err != nil || v <= 0 || v > 65535 {
					return r, fmt.Errorf("capabilities.network: bad port %q", p)
				}
				ports = append(ports, v)
			}
			if len(ports) == 0 {
				ports = []int{0} // порт не задан в настройках — любой
			}
		}
		for _, h := range Expand(n.Host, settings) {
			for _, p := range ports {
				r.Network = append(r.Network, NetworkRule{Host: strings.ToLower(strings.TrimSuffix(h, ".")), Port: p, Scheme: n.Scheme})
			}
		}
	}
	for _, s := range c.Secrets {
		bind := expandAll(s.Bind, settings)
		for _, a := range Expand(s.Alias, settings) {
			if !strings.HasPrefix(a, "@") {
				return r, fmt.Errorf("capabilities.secrets: setting value %q is not a vault alias (@name)", a)
			}
			if len(bind) > 0 {
				r.Secrets = append(r.Secrets, SecretRule{Alias: a, Bind: bind})
			}
		}
	}
	if c.Browser != nil {
		r.Browser = true
		r.BrowserDomains = expandAll(c.Browser.Domains, settings)
	}
	r.Files = expandAll(c.Files, settings)
	if c.Storage != nil {
		r.StorageBytes = int64(c.Storage.QuotaMB) << 20
	}
	return r, nil
}

// Summary — возможности человеческим языком (согласие при установке).
func (c Capabilities) Summary() []string {
	var out []string
	for _, n := range c.Network {
		p := ""
		if n.Port != "" {
			p = ":" + n.Port
		}
		out = append(out, fmt.Sprintf("network %s://%s%s", n.Scheme, n.Host, p))
	}
	for _, s := range c.Secrets {
		out = append(out, fmt.Sprintf("secret %s for %s", s.Alias, strings.Join(s.Bind, ", ")))
	}
	if c.Browser != nil {
		out = append(out, "browser on "+strings.Join(c.Browser.Domains, ", "))
	}
	for _, f := range c.Files {
		out = append(out, "files "+f)
	}
	if c.Storage != nil {
		out = append(out, fmt.Sprintf("storage %d MB", c.Storage.QuotaMB))
	}
	for _, e := range c.Events {
		out = append(out, "events "+e)
	}
	sort.Strings(out)
	return out
}

// Equal — возможности совпадают (для повторного согласия при обновлении).
func (c Capabilities) Equal(o Capabilities) bool {
	a, b := c.Summary(), o.Summary()
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Parse читает манифест из YAML (или JSON — подмножество YAML) и проверяет его.
func Parse(b []byte) (Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("manifest: %w", err)
	}
	normalizeDefaults(&m)
	return m, m.Validate()
}

// normalizeDefaults приводит значения по умолчанию аргументов к типам JSON
// (int из YAML → float64), чтобы манифест из YAML и из JSON совпадали.
func normalizeDefaults(m *Manifest) {
	for i := range m.Actions {
		for j := range m.Actions[i].Args {
			if d := m.Actions[i].Args[j].Default; d != nil {
				b, _ := json.Marshal(d)
				var v any
				_ = json.Unmarshal(b, &v)
				m.Actions[i].Args[j].Default = v
			}
		}
	}
}

// Same — два манифеста совпадают по содержанию (манифест модуля и пакета).
func Same(a, b Manifest) bool {
	normalizeDefaults(&a)
	normalizeDefaults(&b)
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
