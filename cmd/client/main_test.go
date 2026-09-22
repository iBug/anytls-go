package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	path := writeTestConfig(t, `
clients:
  - listen: 127.0.0.1:1080
    server: example.com:443
    password: first
  - listen: "[::1]:1081"
    server: "[2001:db8::1]:8443"
    password: second
`)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Clients) != 2 {
		t.Fatalf("got %d clients, want 2", len(cfg.Clients))
	}
	if cfg.Clients[1].Server != "[2001:db8::1]:8443" {
		t.Fatalf("got second server %q", cfg.Clients[1].Server)
	}
}

func TestLoadConfigRejectsInvalidItems(t *testing.T) {
	tests := map[string]string{
		"no clients":     "clients: []\n",
		"invalid listen": "clients:\n  - listen: '1080'\n    server: example.com:443\n    password: secret\n",
		"invalid server": "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com\n    password: secret\n",
		"empty password": "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: ''\n",
		"unknown field":  "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: secret\n    typo: value\n",
	}

	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := loadConfig(writeTestConfig(t, contents))
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestLoadConfigRejectsMultipleDocuments(t *testing.T) {
	path := writeTestConfig(t, "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: secret\n---\nclients: []\n")

	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("got error %v, want multiple-document error", err)
	}
}

func writeTestConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
