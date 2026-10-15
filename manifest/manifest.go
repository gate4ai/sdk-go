// SPDX-License-Identifier: Apache-2.0

// Package manifest — манифест коннектора gate4.ai: действия, схемы аргументов,
// класс эффекта, способ проверки результата, формат доказательства, среда
// исполнения, возможности (capabilities) и лимиты. Манифест — контракт между
// коннектором и хостом: из него генерируются команды CLI, MCP-инструменты,
// skill и формы Web UI, а возможности обеспечивает среда исполнения.
package manifest

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
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
	Name         string   `json:"name" yaml:"name"`
	Description  string   `json:"description" yaml:"description"`
	Class        string   `json:"class" yaml:"class"`                                     // read | write | external | money
	InputSchema  Schema   `json:"input_schema" yaml:"input_schema"`                       // аргументы (как inputSchema MCP)
	OutputSchema *Schema  `json:"output_schema,omitempty" yaml:"output_schema,omitempty"` // структурированный результат (как outputSchema MCP)
	Verify       string   `json:"verify,omitempty" yaml:"verify,omitempty"`               // метод проверки результата, "" — нет; для money — "<коннектор>.<действие>" другого коннектора
	Evidence     string   `json:"evidence,omitempty" yaml:"evidence,omitempty"`           // формат доказательства: eml, text, png, json
	Untrusted    bool     `json:"untrusted,omitempty" yaml:"untrusted,omitempty"`         // результат содержит недоверенный контент
	Sensitive    []string `json:"sensitive,omitempty" yaml:"sensitive,omitempty"`         // аргументы, которые маскируются в журнале
	Example      string   `json:"example,omitempty" yaml:"example,omitempty"`             // пример вызова CLI
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
		if err := a.InputSchema.validate(""); err != nil {
			return fmt.Errorf("manifest %s.%s: input_schema: %w", m.Connector, a.Name, err)
		}
		if a.OutputSchema != nil {
			if err := a.OutputSchema.validate(""); err != nil {
				return fmt.Errorf("manifest %s.%s: output_schema: %w", m.Connector, a.Name, err)
			}
		}
		for _, n := range a.Sensitive {
			if _, ok := a.InputSchema.Properties.Get(n); !ok {
				return fmt.Errorf("manifest %s.%s: sensitive argument %q is not declared", m.Connector, a.Name, n)
			}
		}
	}
	return nil
}

// ArgError — ошибка нормализации аргументов (отдаётся агенту как invalid_arguments).
type ArgError struct{ Msg string }

func (e *ArgError) Error() string { return e.Msg }

func argErr(f string, a ...any) error { return &ArgError{Msg: fmt.Sprintf(f, a...)} }

// Normalize проверяет аргументы и приводит их к input_schema (см. Schema.Normalize).
func (a Action) Normalize(in map[string]any) (map[string]any, error) {
	return a.InputSchema.Normalize(in)
}

// JSONSchema — inputSchema для MCP.
func (a Action) JSONSchema() map[string]any { return a.InputSchema.JSONSchema() }

// ArgNames — имена аргументов верхнего уровня.
func (a Action) ArgNames() []string { return a.InputSchema.Names() }

func sortStrings(s []string) { sort.Strings(s) }
