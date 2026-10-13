// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"reflect"
	"strings"
	"testing"
)

var send = Action{Name: "send", Class: "external", Args: []Arg{
	{Name: "to", Type: TStrings, Required: true, Format: "email"},
	{Name: "cc", Type: TStrings, Format: "email"},
	{Name: "subject", Type: TString, Required: true},
	{Name: "body", Type: TString},
	{Name: "limit", Type: TInteger, Default: 10.0},
	{Name: "mode", Type: TString, Enum: []string{"plain", "html"}},
}}

func TestNormalize(t *testing.T) {
	got, err := send.Normalize(map[string]any{"to": "Landlord <LandLord@Example.com>", "subject": " Hi "})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"to": []any{"landlord@example.com"}, "cc": []any{}, "subject": "Hi", "body": "", "limit": 10.0, "mode": ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
	bad := []struct {
		in   map[string]any
		want string
	}{
		{map[string]any{"subject": "x"}, `missing required argument "to"`},
		{map[string]any{"to": []any{}, "subject": "x"}, "must not be empty"},
		{map[string]any{"to": "a@b.c", "subject": "x", "bcc": "x"}, "unknown argument(s): bcc"},
		{map[string]any{"to": "not-an-email", "subject": "x"}, "invalid email"},
		{map[string]any{"to": "a@b.c", "subject": 5.0}, "must be a string"},
		{map[string]any{"to": "a@b.c", "subject": "x", "limit": 1.5}, "must be an integer"},
		{map[string]any{"to": "a@b.c", "subject": "x", "mode": "rtf"}, "must be one of"},
		{map[string]any{"to": []any{1.0}, "subject": "x"}, "list of strings"},
	}
	for _, b := range bad {
		if _, err := send.Normalize(b.in); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("%v: want %q, got %v", b.in, b.want, err)
		}
	}
}

func TestSchemaAndValidate(t *testing.T) {
	s := send.JSONSchema()
	if s["required"].([]string)[0] != "to" || s["properties"].(map[string]any)["to"].(map[string]any)["type"] != "array" {
		t.Fatalf("%v", s)
	}
	m := Manifest{Connector: "email", Actions: []Action{send}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.Actions = append(m.Actions, Action{Name: "send", Class: "read"})
	if m.Validate() == nil {
		t.Fatal("duplicate must fail")
	}
	m.Actions = []Action{{Name: "x", Class: "dangerous"}}
	if m.Validate() == nil {
		t.Fatal("bad class must fail")
	}
}
