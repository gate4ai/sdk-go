// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gate4ai/sdk-go/abi"
	"github.com/gate4ai/sdk-go/manifest"
)

func isDenied(err error) bool {
	var e *abi.Error
	return errors.As(err, &e) && e.Code == abi.CodeCapabilityDenied
}

func checker(t *testing.T, yaml string, settings map[string]any, home string) *Checker {
	t.Helper()
	m, err := manifest.Parse([]byte("connector: x\n" + yaml))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(m, settings, home)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNetworkAndSecrets(t *testing.T) {
	c := checker(t, `capabilities:
  network:
    - { host: api.example.com, port: "443", scheme: https }
    - { host: "*.cdn.example.com", scheme: https }
    - { host: localhost, scheme: http }
    - { host: mail.example.com, scheme: tls }
  secrets:
    - { alias: "@api", bind: [api.example.com] }
`, nil, "")
	ok := []struct {
		s, h string
		p    int
	}{{"https", "api.example.com", 443}, {"https", "img.cdn.example.com", 8443}, {"http", "localhost", 8080}, {"tls", "MAIL.example.com.", 993}}
	for _, x := range ok {
		if err := c.Network(x.s, x.h, x.p); err != nil {
			t.Errorf("%v: %v", x, err)
		}
	}
	bad := []struct {
		s, h string
		p    int
	}{{"https", "api.example.com", 8443}, {"https", "cdn.example.com", 443}, {"http", "api.example.com", 80}, {"tcp", "mail.example.com", 25}, {"https", "evil.com", 443}}
	for _, x := range bad {
		if err := c.Network(x.s, x.h, x.p); !isDenied(err) {
			t.Errorf("%v allowed: %v", x, err)
		}
	}
	if err := c.Secret("@api", "api.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secret("@api", "evil.com"); !isDenied(err) {
		t.Fatal("secret for unbound host")
	}
	if err := c.Secret("@other", "api.example.com"); !isDenied(err) {
		t.Fatal("undeclared secret")
	}
	if err := c.BrowserDeclared(); !isDenied(err) {
		t.Fatal("browser not declared")
	}
	if _, err := c.Storage(); !isDenied(err) {
		t.Fatal("storage not declared")
	}
	if _, err := c.Path("/tmp/x"); !isDenied(err) {
		t.Fatal("files not declared")
	}
}

func TestPaths(t *testing.T) {
	home := t.TempDir()
	notes := filepath.Join(home, "notes")
	os.MkdirAll(filepath.Join(notes, "sub"), 0o755)
	secret := filepath.Join(home, "secret")
	os.MkdirAll(secret, 0o755)
	os.WriteFile(filepath.Join(secret, "key"), []byte("k"), 0o600)
	os.Symlink(secret, filepath.Join(notes, "link"))
	one := filepath.Join(home, "todo.md")
	c := checker(t, `capabilities: { files: ["${setting:roots}/**", "`+one+`"] }`, map[string]any{"roots": []any{"~/notes"}}, home)
	for _, p := range []string{"~/notes/a.md", notes + "/sub/b.md", notes, one} {
		if _, err := c.Path(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"~/notes/../secret/key", notes + "/link/key", "notes/a.md", home + "/other.md", "~/notes2/x"} {
		if _, err := c.Path(p); !isDenied(err) {
			t.Errorf("%s allowed: %v", p, err)
		}
	}
	if err := checker(t, `capabilities: { browser: { domains: ["${setting:allowed}"] } }`, map[string]any{"allowed": []any{"*.bank.example"}}, "").Browser("https://lk.bank.example/x"); err != nil {
		t.Fatal(err)
	}
}
