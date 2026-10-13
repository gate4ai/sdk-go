// SPDX-License-Identifier: Apache-2.0

// Package manifest — манифест коннектора gate4.ai: действия, схемы аргументов,
// класс эффекта, способ проверки результата, формат доказательства, среда
// исполнения, возможности (capabilities) и лимиты. Манифест — контракт между
// коннектором и хостом: из него генерируются команды CLI, MCP-инструменты,
// skill и формы Web UI, а возможности обеспечивает среда исполнения.
package manifest

import (
	"fmt"
	"net/mail"
	"regexp"
	"sort"
	"strings"
)

// Типы аргументов.
const (
	TString  = "string"
	TNumber  = "number"
	TInteger = "integer"
	TBoolean = "boolean"
	TStrings = "string[]"
)

// Среды исполнения.
const (
	RuntimeWasm    = "wasm"    // WASM-модуль в хосте (wazero), только функции хоста
	RuntimeNative  = "native"  // процесс в песочнице (позже)
	RuntimeBuiltin = "builtin" // внутренний коннектор хоста (не из магазина)
)

// Manifest — описание коннектора.
type Manifest struct {
	Connector    string       `json:"connector" yaml:"connector"`
	Description  string       `json:"description" yaml:"description"`
	Version      string       `json:"version" yaml:"version"`
	Runtime      string       `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	Capabilities Capabilities `json:"capabilities" yaml:"capabilities"`
	Limits       Limits       `json:"limits" yaml:"limits"`
	Actions      []Action     `json:"actions" yaml:"actions"`
}

// Action — действие коннектора.
type Action struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	Class       string   `json:"class" yaml:"class"` // read | write | external | money
	Args        []Arg    `json:"args" yaml:"args"`
	Verify      string   `json:"verify,omitempty" yaml:"verify,omitempty"`       // метод проверки результата, "" — нет; для money — "<коннектор>.<действие>" другого коннектора
	Evidence    string   `json:"evidence,omitempty" yaml:"evidence,omitempty"`   // формат доказательства: eml, text, png, json
	Untrusted   bool     `json:"untrusted,omitempty" yaml:"untrusted,omitempty"` // результат содержит недоверенный контент
	Sensitive   []string `json:"sensitive,omitempty" yaml:"sensitive,omitempty"` // аргументы, которые маскируются в журнале
	Example     string   `json:"example,omitempty" yaml:"example,omitempty"`     // пример вызова CLI
}

// Arg — аргумент действия.
type Arg struct {
	Name        string   `json:"name" yaml:"name"`
	Type        string   `json:"type" yaml:"type"`
	Required    bool     `json:"required,omitempty" yaml:"required,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Default     any      `json:"default,omitempty" yaml:"default,omitempty"`
	Enum        []string `json:"enum,omitempty" yaml:"enum,omitempty"`
	Format      string   `json:"format,omitempty" yaml:"format,omitempty"` // email | url | path
}

// Full — полное имя действия "connector.action".
func (m *Manifest) Full(a Action) string { return m.Connector + "." + a.Name }

// Find ищет действие по короткому имени.
func (m *Manifest) Find(name string) (Action, bool) {
	for _, a := range m.Actions {
		if a.Name == name {
			return a, true
		}
	}
	return Action{}, false
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Validate проверяет манифест.
func (m *Manifest) Validate() error {
	if !nameRe.MatchString(m.Connector) {
		return fmt.Errorf("manifest: bad connector name %q", m.Connector)
	}
	switch m.Runtime {
	case "", RuntimeWasm, RuntimeNative, RuntimeBuiltin:
	default:
		return fmt.Errorf("manifest %s: bad runtime %q", m.Connector, m.Runtime)
	}
	if err := m.Capabilities.validate(); err != nil {
		return fmt.Errorf("manifest %s: %w", m.Connector, err)
	}
	if m.Limits.MemoryMB < 0 || m.Limits.TimeoutS < 0 || m.Limits.VerifyDeadlineS < 0 {
		return fmt.Errorf("manifest %s: negative limits", m.Connector)
	}
	seen := map[string]bool{}
	for _, a := range m.Actions {
		if !nameRe.MatchString(a.Name) || seen[a.Name] {
			return fmt.Errorf("manifest %s: bad or duplicate action %q", m.Connector, a.Name)
		}
		seen[a.Name] = true
		switch a.Class {
		case "read", "write", "external", "money":
		default:
			return fmt.Errorf("manifest %s.%s: bad class %q", m.Connector, a.Name, a.Class)
		}
		// Коннектор не подтверждает сам себя: проверка money — действием другого коннектора.
		if a.Class == "money" {
			other, _, ok := strings.Cut(a.Verify, ".")
			if !ok || other == m.Connector || !nameRe.MatchString(other) {
				return fmt.Errorf("manifest %s.%s: class money needs verify by another connector (\"<connector>.<action>\")", m.Connector, a.Name)
			}
		}
		an := map[string]bool{}
		for _, g := range a.Args {
			if !nameRe.MatchString(g.Name) || an[g.Name] {
				return fmt.Errorf("manifest %s.%s: bad or duplicate arg %q", m.Connector, a.Name, g.Name)
			}
			an[g.Name] = true
			switch g.Type {
			case TString, TNumber, TInteger, TBoolean, TStrings:
			default:
				return fmt.Errorf("manifest %s.%s: arg %s: bad type %q", m.Connector, a.Name, g.Name, g.Type)
			}
		}
	}
	return nil
}

// ArgError — ошибка нормализации аргументов (отдаётся агенту как invalid_arguments).
type ArgError struct{ Msg string }

func (e *ArgError) Error() string { return e.Msg }

func argErr(f string, a ...any) error { return &ArgError{Msg: fmt.Sprintf(f, a...)} }

// Normalize проверяет и приводит аргументы к схеме: неизвестные аргументы —
// ошибка, обязательные — должны быть, отсутствующие необязательные получают
// значение по умолчанию или нулевое значение типа (чтобы условия CEL не падали).
// Числа — float64, списки строк — []any из строк, адреса email — в нижнем регистре.
func (a Action) Normalize(in map[string]any) (map[string]any, error) {
	out := map[string]any{}
	known := map[string]Arg{}
	for _, g := range a.Args {
		known[g.Name] = g
	}
	var unknown []string
	for k := range in {
		if _, ok := known[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, argErr("unknown argument(s): %s", strings.Join(unknown, ", "))
	}
	for _, g := range a.Args {
		v, ok := in[g.Name]
		if !ok || v == nil {
			if g.Required {
				return nil, argErr("missing required argument %q", g.Name)
			}
			v = g.Default
			if v == nil {
				v = zero(g.Type)
			}
		}
		nv, err := coerce(g, v)
		if err != nil {
			return nil, err
		}
		if g.Required && (nv == "" || isEmptyList(nv)) {
			return nil, argErr("argument %q must not be empty", g.Name)
		}
		out[g.Name] = nv
	}
	return out, nil
}

func zero(t string) any {
	switch t {
	case TNumber, TInteger:
		return float64(0)
	case TBoolean:
		return false
	case TStrings:
		return []any{}
	}
	return ""
}

func isEmptyList(v any) bool {
	l, ok := v.([]any)
	return ok && len(l) == 0
}

func coerce(g Arg, v any) (any, error) {
	switch g.Type {
	case TString:
		s, ok := v.(string)
		if !ok {
			return nil, argErr("argument %q must be a string", g.Name)
		}
		return normString(g, s)
	case TNumber, TInteger:
		var f float64
		switch n := v.(type) {
		case float64:
			f = n
		case int:
			f = float64(n)
		case int64:
			f = float64(n)
		default:
			return nil, argErr("argument %q must be a number", g.Name)
		}
		if g.Type == TInteger && f != float64(int64(f)) {
			return nil, argErr("argument %q must be an integer", g.Name)
		}
		return f, nil
	case TBoolean:
		b, ok := v.(bool)
		if !ok {
			return nil, argErr("argument %q must be a boolean", g.Name)
		}
		return b, nil
	case TStrings:
		var items []any
		switch l := v.(type) {
		case string:
			items = []any{l}
		case []string:
			for _, s := range l {
				items = append(items, s)
			}
		case []any:
			items = l
		default:
			return nil, argErr("argument %q must be a list of strings", g.Name)
		}
		out := make([]any, 0, len(items))
		for _, it := range items {
			s, ok := it.(string)
			if !ok {
				return nil, argErr("argument %q must be a list of strings", g.Name)
			}
			ns, err := normString(g, s)
			if err != nil {
				return nil, err
			}
			out = append(out, ns)
		}
		return out, nil
	}
	return nil, argErr("argument %q: unsupported type", g.Name)
}

func normString(g Arg, s string) (any, error) {
	s = strings.TrimSpace(s)
	if len(g.Enum) > 0 && s != "" {
		ok := false
		for _, e := range g.Enum {
			ok = ok || e == s
		}
		if !ok {
			return nil, argErr("argument %q must be one of: %s", g.Name, strings.Join(g.Enum, ", "))
		}
	}
	if s == "" {
		return s, nil
	}
	switch g.Format {
	case "email":
		addr, err := mail.ParseAddress(s)
		if err != nil {
			return nil, argErr("argument %q: invalid email address %q", g.Name, s)
		}
		return strings.ToLower(addr.Address), nil
	case "url":
		if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
			return nil, argErr("argument %q: only http(s) URLs are allowed", g.Name)
		}
	}
	return s, nil
}

// JSONSchema — JSON Schema аргументов (для MCP inputSchema).
func (a Action) JSONSchema() map[string]any {
	props := map[string]any{}
	req := []string{}
	for _, g := range a.Args {
		p := map[string]any{}
		switch g.Type {
		case TStrings:
			p["type"] = "array"
			p["items"] = map[string]any{"type": "string"}
		default:
			p["type"] = g.Type
		}
		if g.Description != "" {
			p["description"] = g.Description
		}
		if len(g.Enum) > 0 {
			p["enum"] = g.Enum
		}
		if g.Format == "email" || g.Format == "uri" {
			p["format"] = g.Format
		}
		if g.Default != nil {
			p["default"] = g.Default
		}
		props[g.Name] = p
		if g.Required {
			req = append(req, g.Name)
		}
	}
	return map[string]any{"type": "object", "properties": props, "required": req, "additionalProperties": false}
}

// ArgNames — имена аргументов.
func (a Action) ArgNames() []string {
	out := make([]string, len(a.Args))
	for i, g := range a.Args {
		out[i] = g.Name
	}
	return out
}
