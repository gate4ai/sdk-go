// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const sendYAML = `
connector: email
actions:
  - name: send
    class: external
    input_schema:
      type: object
      properties:
        to: { type: array, items: { type: string, format: email } }
        cc: { type: array, items: { type: string, format: email } }
        subject: { type: string, maxLength: 20 }
        body: { type: string }
        limit: { type: integer, default: 10, minimum: 1 }
        mode: { type: string, enum: [plain, html] }
        attachments:
          type: array
          items:
            type: object
            properties:
              name: { type: string }
              size: { type: integer }
            required: [name]
      required: [to, subject]
    output_schema:
      type: object
      properties:
        message_id: { type: string }
        recipients: { type: array, items: { type: string } }
      required: [message_id]
`

func sendAction(t *testing.T) Action {
	t.Helper()
	m, err := Parse([]byte(sendYAML))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := m.Find("send")
	return a
}

func TestNormalize(t *testing.T) {
	send := sendAction(t)
	got, err := send.Normalize(map[string]any{"to": "Landlord <LandLord@Example.com>", "subject": " Hi ",
		"attachments": []any{map[string]any{"name": " a.pdf "}}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"to": []any{"landlord@example.com"}, "cc": []any{}, "subject": "Hi", "body": "", "limit": 10.0, "mode": "",
		"attachments": []any{map[string]any{"name": "a.pdf", "size": 0.0}}}
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
		{map[string]any{"to": "a@b.c", "subject": "x", "limit": 0.0}, "out of range"},
		{map[string]any{"to": "a@b.c", "subject": strings.Repeat("x", 21)}, "too long"},
		{map[string]any{"to": "a@b.c", "subject": "x", "mode": "rtf"}, "must be one of"},
		{map[string]any{"to": []any{1.0}, "subject": "x"}, `"to[0]" must be a string`},
		{map[string]any{"to": "a@b.c", "subject": "x", "attachments": []any{map[string]any{}}}, `missing required argument "attachments[0].name"`},
		{map[string]any{"to": "a@b.c", "subject": "x", "attachments": []any{map[string]any{"name": "a", "x": 1.0}}}, "unknown argument(s): attachments[0].x"},
		{map[string]any{"to": "a@b.c", "subject": "x", "attachments": "a.pdf"}, "must be an array"},
	}
	for _, b := range bad {
		if _, err := send.Normalize(b.in); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("%v: want %q, got %v", b.in, b.want, err)
		}
	}
}

func TestSchemaOrderAndJSON(t *testing.T) {
	send := sendAction(t)
	if got := strings.Join(send.ArgNames(), ","); got != "to,cc,subject,body,limit,mode,attachments" {
		t.Fatalf("order: %s", got)
	}
	// Порядок полей переживает JSON (манифест модуля приходит хосту в JSON).
	b, _ := json.Marshal(send)
	var back Action
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.ArgNames(), send.ArgNames()) {
		t.Fatalf("json order: %v", back.ArgNames())
	}
	s := send.JSONSchema()
	if s["required"].([]string)[0] != "to" || s["additionalProperties"] != false {
		t.Fatalf("%v", s)
	}
	att := s["properties"].(map[string]any)["attachments"].(map[string]any)["items"].(map[string]any)
	if att["additionalProperties"] != false || att["required"].([]string)[0] != "name" {
		t.Fatalf("nested: %v", att)
	}
}

func TestCheck(t *testing.T) {
	out := sendAction(t).OutputSchema
	if err := out.Check(map[string]any{"message_id": "<1@x>", "recipients": []any{"a@b.c"}}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{
		map[string]any{},
		map[string]any{"message_id": 1.0},
		map[string]any{"message_id": "x", "extra": true},
		map[string]any{"message_id": "x", "recipients": []any{1.0}},
		"x",
	} {
		if out.Check(v) == nil {
			t.Errorf("%v must fail", v)
		}
	}
}

func TestValidate(t *testing.T) {
	m := Manifest{Connector: "email", Actions: []Action{sendAction(t)}}
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
	bad := []string{
		"input_schema: { type: string }",
		"input_schema: { type: object, properties: { a: { type: array } } }",
		"input_schema: { type: object, properties: { a: { type: number, enum: [x] } } }",
		"input_schema: { type: object, properties: { a: { type: string, format: phone } } }",
		"input_schema: { type: object, properties: { a: { type: string } }, required: [b] }",
		"input_schema: { type: object, additionalProperties: true }",
		"input_schema: { type: object, properties: { a: { type: string, pattern: x } } }",
		"input_schema: { type: object, properties: { a: { type: string } } }\n    sensitive: [b]",
	}
	if _, err := Parse([]byte("connector: x\nactions:\n  - { name: a, class: read, args: [] }\n")); err == nil || !strings.Contains(err.Error(), "ABI v1") {
		t.Fatal("ABI v1 manifest must fail with a clear error", err)
	}
	for _, b := range bad {
		y := "connector: x\nactions:\n  - name: a\n    class: read\n    " + b + "\n"
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: must fail", b)
		}
	}
}
