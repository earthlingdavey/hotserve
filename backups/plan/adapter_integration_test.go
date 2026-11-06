//go:build integration

package plan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The plan step's refusal of an import glob that matches nothing rests
// on the words of Caddy's own warning, in the form Caddy logs it when
// its stderr is not a terminal (emptyGlobs). Were a Caddy bump to word
// or shape that line otherwise, the refusal would be gone, and with it
// the one thing that stops a run planning without the apps a view
// cannot see — silently. So it is held to the real adapter, built from
// this repository, here and not only in e2e.
func TestIntegrationTheAdapterWarnsOfAnEmptyGlobAsTheRefusalReadsIt(t *testing.T) {
	realAdapter(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "Caddyfile")
	site := "http://:8080 {\n\trespond hi\n}\n"
	outside := filepath.Join(t.TempDir(), "apps", "*.caddy")
	if err := os.WriteFile(file, []byte("import "+outside+"\n"+site), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Make(context.Background(), file)
	if err == nil || !strings.Contains(err.Error(), outside+", which matches no file") {
		t.Fatalf("Make of a Caddyfile whose import glob matches nothing: %v", err)
	}

	// And one that matches is taken: the refusal is of the warning, not
	// of every import.
	if err := os.MkdirAll(filepath.Join(dir, "sites"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sites", "a.caddy"), []byte("# nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("import sites/*.caddy\n"+site), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Make(context.Background(), file); err != nil {
		t.Fatalf("Make of a glob that matches: %v", err)
	}
}

// A variable no made-up value adapts with is refused where a trial
// failed at an import and let through where every trial was refused by
// a directive checking its argument's form (#394). Which is which is
// read off the adapter's words, as emptyGlobs reads its warning: the
// parser's "File to import not found" and "Could not import" with no
// prefix, a directive's own behind the HTTP adapter's "parsing
// caddyfile tokens for '…':". Were a Caddy bump to change the first,
// an import through a variable would still be refused, in the words
// for neither; were it to change the second, `protocols
// {$TLS_MIN:tls1.2}` would be refused again, as before #394 — so both
// are held here, on the adapter's own stderr, where Make's verdict
// alone could not tell.
func TestIntegrationTheAdapterRefusesAnImportAndADirectiveAsInspectReadsThem(t *testing.T) {
	realAdapter(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "Caddyfile")
	if err := os.MkdirAll(filepath.Join(dir, "sites", "prod"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join("sites", "prod.caddy"), filepath.Join("sites", "prod", "a.caddy")} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("# what the default imports\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	said := func(caddyfile string, env ...string) string {
		t.Helper()
		if err := os.WriteFile(file, []byte(caddyfile), 0o644); err != nil {
			t.Fatal(err)
		}
		adapt := exec.Command(motel, "adapt", "--adapter", "caddyfile", "--config", file)
		adapt.Env = append([]string{}, env...) // never nil: nil means "inherit"
		var stderr strings.Builder
		adapt.Stderr = &stderr
		_ = adapt.Run()
		return stderr.String()
	}
	const site = "example.com {\n\ttls {\n\t\tprotocols {$TLS_MIN:tls1.2}\n\t}\n\trespond ok\n}\n"
	for name, tc := range map[string]struct {
		said                  string
		atImport, atDirective bool
	}{
		"a directive's check":     {said(site, "TLS_MIN=1"), false, true},
		"a file to import":        {said("import sites/{$ENV:prod}.caddy\n"+site, "ENV=1"), true, false},
		"a directory to import":   {said("import {$F:sites/prod.caddy}\n"+site, "F=sites"), true, false},
		"a glob, and a directive": {said("import sites/{$ENV:prod}/*.caddy\nexample.com {\n\ttls {\n\t\tprotocols {$ENV:tls1.2}\n\t}\n}\n", "ENV=1"), true, true},
	} {
		if failedAtImport(tc.said) != tc.atImport || failedAtDirective(tc.said) != tc.atDirective {
			t.Errorf("%s: import %v, directive %v, want %v, %v; the adapter said:\n%s", name, failedAtImport(tc.said), failedAtDirective(tc.said), tc.atImport, tc.atDirective, tc.said)
		}
	}

	// And so Make: the one let through, the other refused by name.
	if err := os.WriteFile(file, []byte(site), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Make(context.Background(), file); err != nil {
		t.Fatalf("Make of a value the tls directive checks by form: %v", err)
	}
	if err := os.WriteFile(file, []byte("import sites/{$ENV:prod}.caddy\n"+site), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Make(context.Background(), file); err == nil || !strings.Contains(err.Error(), "imports through the environment variable(s) ENV") {
		t.Fatalf("Make of an import through a variable: %v", err)
	}

	// A snippet's argument reaches its {args[0]}, here the root: no
	// trial adapts (the tls check refuses each), and each occurrence
	// tried on its own finds the root moved — however the lexer chains
	// the occurrence onto its line.
	snippet := "(where) {\n\troot /srv/{args[0]}\n}\n{\n\tadmin off\n\tliveswap {\n\t\timport where {$X:tls1.2}\n\t\tartifact_allowlist example.com/\n\t\tdeploy_trust github {\n\t\t\taudience motel\n\t\t\tclaim repository your-org/app\n\t\t}\n\t\tapp blog {\n\t\t\tcommand ./server\n\t\t\tbackup {\n\t\t\t\tsqlite app.db\n\t\t\t}\n\t\t}\n\t}\n}\n" + strings.Replace(site, "TLS_MIN", "X", 1)
	if out := said(snippet); strings.Contains(out, "\"level\":\"error\"") {
		t.Fatalf("fixture: the snippet Caddyfile does not adapt with its defaults: %s", out)
	}
	if _, err := Make(context.Background(), file); err == nil || !strings.Contains(err.Error(), "depends on the environment variable(s) X") {
		t.Fatalf("Make of a root reached through a snippet's argument: %v", err)
	}
	for name, form := range map[string]string{
		"chained by a backslash": "import where \\\n\t\t\t{$X:tls1.2}",
		"quoted":                 "import where \"{$X:tls1.2}\"",
	} {
		if out := said(strings.Replace(snippet, "import where {$X:tls1.2}", form, 1)); strings.Contains(out, "\"level\":\"error\"") {
			t.Fatalf("fixture: the Caddyfile %s does not adapt with its defaults: %s", name, out)
		}
		if _, err := Make(context.Background(), file); err == nil || !strings.Contains(err.Error(), "depends on the environment variable(s) X") {
			t.Fatalf("Make of a root reached through a snippet argument %s: %v", name, err)
		}
	}

	// A snippet's argument used twice — for the root and for the
	// protocols check, one import — is refused by the check quoting the
	// value from the snippet's line, not the import's (the adapter names
	// the import's line after it, in the import chain): where else it
	// went is not told.
	twice := "(site) {\n\t{\n\t\tadmin off\n\t\tliveswap {\n\t\t\troot /srv/{args[0]}\n\t\t\tartifact_allowlist example.com/\n\t\t\tdeploy_trust github {\n\t\t\t\taudience motel\n\t\t\t\tclaim repository your-org/app\n\t\t\t}\n\t\t\tapp blog {\n\t\t\t\tcommand ./server\n\t\t\t\tbackup {\n\t\t\t\t\tsqlite app.db\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n\texample.com {\n\t\ttls {\n\t\t\tprotocols {args[0]}\n\t\t}\n\t}\n}\nimport site {$X:tls1.2}\n"
	if out := said(twice); strings.Contains(out, "\"level\":\"error\"") {
		t.Fatalf("fixture: the Caddyfile with the argument used twice does not adapt with its defaults: %s", out)
	}
	if _, err := Make(context.Background(), file); err == nil || !strings.Contains(err.Error(), "could not be told") {
		t.Fatalf("Make with a snippet argument used twice: %v", err)
	}

	// An occurrence the copy does not hold — in a file imported by its
	// absolute path, which the adapter reads where it is — is seen, and
	// the variable refused as not knowable here.
	if err := os.WriteFile(filepath.Join(dir, "sites", "hdr.caddy"), []byte("header_up X-Env {$X:tls1.2}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("example.com {\n\ttls {\n\t\tprotocols {$X:tls1.2}\n\t}\n\treverse_proxy a:1 {\n\t\timport "+filepath.Join(dir, "sites", "hdr.caddy")+"\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Make(context.Background(), file); err == nil || !strings.Contains(err.Error(), "could not be told") {
		t.Fatalf("Make with an occurrence past the copy: %v", err)
	}
	// A refusal is placed where the lexer places the token: at the start
	// of its chain, with the lines the chain spans counted again after
	// it — so the chained occurrence and the inert one after it are both
	// found where the adapter says.
	if err := os.WriteFile(file, []byte("example.com {\n\ttls {\n\t\tprotocols \\\n\t\t\t{$X:tls1.2}\n\t}\n\treverse_proxy a:1 {\n\t\theader_up X-Env {$X:tls1.2}\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Make(context.Background(), file); err != nil {
		t.Fatalf("Make with a chained occurrence and one after it: %v", err)
	}
	// Imported by a relative path, the same file is in the copy: let through.
	if err := os.WriteFile(file, []byte("example.com {\n\ttls {\n\t\tprotocols {$X:tls1.2}\n\t}\n\treverse_proxy a:1 {\n\t\timport sites/hdr.caddy\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Make(context.Background(), file); err != nil {
		t.Fatalf("Make with the occurrence in the copy: %v", err)
	}
}

// The adapter, motel built from this repository: once, by the first
// test that asks, and removed after the last (TestMain).
var (
	adapterOnce sync.Once
	adapterDir  string
	adapterErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if adapterDir != "" {
		_ = os.RemoveAll(adapterDir)
	}
	os.Exit(code)
}

// realAdapter has Make adapt with the real adapter for the rest of the
// test.
func realAdapter(t *testing.T) {
	t.Helper()
	adapterOnce.Do(func() {
		root, err := filepath.Abs("../..") // the workspace: the motel module is its root
		if err != nil {
			adapterErr = err
			return
		}
		if adapterDir, adapterErr = os.MkdirTemp("", "plan-adapter-"); adapterErr != nil {
			return
		}
		build := exec.Command("go", "build", "-o", filepath.Join(adapterDir, "motel"), "./cmd/motel")
		build.Dir = root
		if out, err := build.CombinedOutput(); err != nil {
			adapterErr = fmt.Errorf("building motel: %w\n%s", err, out)
		}
	})
	if adapterErr != nil {
		t.Fatal(adapterErr)
	}
	old := motel
	motel = filepath.Join(adapterDir, "motel")
	t.Cleanup(func() { motel = old })
}

// A run adapts the Caddyfile without the server's environment, and what
// it reads of {$NAME} rests on how Caddy substitutes it: in the text,
// before any module sees a token; unset, with no default, as nothing —
// which makes `email {$ACME_EMAIL}` no Caddyfile at all; and
// {$NAME:default} as the default. So Make gives a variable with no
// default a made-up value of the kind its place takes, and refuses one
// whose value moves the root or a backup path, naming it (Inspect).
// Held to the real adapter, as the empty-glob warning is.
func TestIntegrationTheAdapterSubstitutesVariablesAsMakeReadsThem(t *testing.T) {
	realAdapter(t)
	const apps = `
	liveswap {
		root %s
		artifact_allowlist example.com/
		deploy_trust github {
			audience motel
			claim repository your-org/app
		}
		app blog {
			command ./server
			backup {
				sqlite app.db
				files  uploads
			}
		}
	}
`
	write := func(global, root, sites string) string {
		t.Helper()
		file := filepath.Join(t.TempDir(), "Caddyfile")
		if err := os.WriteFile(file, []byte("{\n\tadmin off\n"+global+strings.Replace(apps, "%s", root, 1)+"}\n\n"+sites), 0o644); err != nil {
			t.Fatal(err)
		}
		return file
	}

	// An ordinary production Caddyfile: variables with no default.
	file := write("\temail {$ACME_EMAIL}\n", "/var/lib/liveswap", ":{$METRICS_PORT} {\n\trespond metrics\n}\n\n{$SITE_DOMAIN} {\n\trespond ok\n}\n")
	adapt := exec.Command(motel, "adapt", "--adapter", "caddyfile", "--config", file)
	adapt.Env = []string{}
	if out, err := adapt.CombinedOutput(); err == nil {
		t.Fatalf("fixture: with an empty environment this Caddyfile adapts, so the test proves nothing: %s", out)
	}
	p, err := Make(context.Background(), file)
	if err != nil || p.Root != "/var/lib/liveswap" || p.Apps["blog"] == nil {
		t.Fatalf("Make of a Caddyfile whose variables have no default: %+v, %v", p, err)
	}

	// A root the server and a run would read differently.
	file = write("", "{$LIVESWAP_ROOT:/var/lib/liveswap}", ":8080 {\n\trespond ok\n}\n")
	if _, err := Make(context.Background(), file); err == nil || !strings.Contains(err.Error(), "depends on the environment variable(s) LIVESWAP_ROOT") {
		t.Fatalf("Make of a root written {$LIVESWAP_ROOT:…}: %v", err)
	}
}
