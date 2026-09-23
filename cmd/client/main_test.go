package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	path := writeTestConfig(t, `
clients:
  - listen: 127.0.0.1:1080
    server: example.com:443
    password: first
    sni: first.example.com
    min-idle: 8
    disable-reuse: true
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
	if cfg.Clients[0].SNI != "first.example.com" || cfg.Clients[0].minIdle() != 8 || !cfg.Clients[0].DisableReuse {
		t.Fatalf("got first client settings %+v", cfg.Clients[0])
	}
	if cfg.Clients[1].SNI != "" || cfg.Clients[1].minIdle() != 5 || cfg.Clients[1].DisableReuse {
		t.Fatalf("got second client defaults %+v", cfg.Clients[1])
	}
}

func TestLoadConfigRejectsInvalidItems(t *testing.T) {
	tests := map[string]string{
		"no clients":        "clients: []\n",
		"invalid listen":    "clients:\n  - listen: '1080'\n    server: example.com:443\n    password: secret\n",
		"invalid server":    "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com\n    password: secret\n",
		"empty password":    "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: ''\n",
		"negative min idle": "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: secret\n    min-idle: -1\n",
		"unknown field":     "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: secret\n    typo: value\n",
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

func TestReloadInvalidConfigLeavesListenersUntouched(t *testing.T) {
	path := writeTestConfig(t, testClientConfig("127.0.0.1:0", "first.example:443"))
	manager := newListenerManager(context.Background(), path, nil)
	if err := manager.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.active.retire() })

	active := manager.active
	address := active.listeners[0].listener.Addr().String()
	if err := os.WriteFile(path, []byte("clients: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.reload(); err == nil {
		t.Fatal("expected invalid reload to fail")
	}
	if manager.active != active {
		t.Fatal("invalid reload replaced the active listener set")
	}
	assertDialSucceeds(t, address)
}

func TestReloadReplacesListeners(t *testing.T) {
	oldAddress := freeTCPAddress(t)
	newAddress := freeTCPAddress(t)
	path := writeTestConfig(t, testClientConfig(oldAddress, "first.example:443"))
	manager := newListenerManager(context.Background(), path, nil)
	if err := manager.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.active.retire() })

	oldSet := manager.active
	if err := os.WriteFile(path, []byte(testClientConfig(newAddress, "second.example:443")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.reload(); err != nil {
		t.Fatal(err)
	}
	if manager.active == oldSet {
		t.Fatal("valid reload did not replace the active listener set")
	}
	if manager.config.Clients[0].Server != "second.example:443" {
		t.Fatalf("got server %q after reload", manager.config.Clients[0].Server)
	}
	assertDialFails(t, oldAddress)
	assertDialSucceeds(t, newAddress)
}

func TestReloadReusesUnchangedListenAddress(t *testing.T) {
	address := freeTCPAddress(t)
	path := writeTestConfig(t, testClientConfig(address, "first.example:443"))
	manager := newListenerManager(context.Background(), path, nil)
	if err := manager.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.active.retire() })

	oldListener := manager.active.listeners[0]
	oldSocket := oldListener.listener
	oldGeneration := oldListener.currentGeneration()
	if err := os.WriteFile(path, []byte(testClientConfig(address, "second.example:443")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.reload(); err != nil {
		t.Fatal(err)
	}
	listener := manager.active.listeners[0]
	if listener != oldListener {
		t.Fatal("reload replaced the listener for an unchanged address")
	}
	if listener.listener != oldSocket {
		t.Fatal("reload replaced the socket for an unchanged address")
	}
	if listener.currentGeneration() == oldGeneration {
		t.Fatal("reload did not update the reused listener's client generation")
	}
	if listener.currentGeneration().config.Server != "second.example:443" {
		t.Fatalf("got server %q after reload", listener.currentGeneration().config.Server)
	}
	assertDialSucceeds(t, address)
}

func TestReloadBindFailureDoesNotUpdateReusedListener(t *testing.T) {
	address := freeTCPAddress(t)
	path := writeTestConfig(t, testClientConfig(address, "first.example:443"))
	manager := newListenerManager(context.Background(), path, nil)
	if err := manager.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manager.active.retire() })

	active := manager.active
	listener := active.listeners[0]
	generation := listener.currentGeneration()
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocked.Close() })

	contents := testClientConfig(address, "second.example:443") + fmt.Sprintf("  - listen: %s\n    server: third.example:443\n    password: secret\n    min-idle: 0\n", blocked.Addr())
	if err = os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if err = manager.reload(); err == nil {
		t.Fatal("expected reload with an occupied new address to fail")
	}
	if manager.active != active || manager.active.listeners[0] != listener {
		t.Fatal("failed reload replaced the active listener set")
	}
	if listener.currentGeneration() != generation {
		t.Fatal("failed reload updated a reused listener's client generation")
	}
	if listener.currentGeneration().config.Server != "first.example:443" {
		t.Fatalf("got server %q after failed reload", listener.currentGeneration().config.Server)
	}
	assertDialSucceeds(t, address)
}

func testClientConfig(listen, server string) string {
	return fmt.Sprintf("clients:\n  - listen: %s\n    server: %s\n    password: secret\n    min-idle: 0\n", listen, server)
}

func freeTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func assertDialSucceeds(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	_ = conn.Close()
}

func assertDialFails(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("dial to retired listener %s succeeded", address)
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
