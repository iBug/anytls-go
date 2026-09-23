package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
	if !assert.NoError(t, err) {
		return
	}
	assert.Len(t, cfg.Clients, 2)
	assert.Equal(t, "[2001:db8::1]:8443", cfg.Clients[1].Server)
	assert.Equal(t, "first.example.com", cfg.Clients[0].SNI)
	assert.Equal(t, 8, cfg.Clients[0].minIdle())
	assert.True(t, cfg.Clients[0].DisableReuse)
	assert.Empty(t, cfg.Clients[1].SNI)
	assert.Equal(t, 5, cfg.Clients[1].minIdle())
	assert.False(t, cfg.Clients[1].DisableReuse)
}

func TestLoadConfigRejectsInvalidItems(t *testing.T) {
	tests := map[string]string{
		"no clients":        "clients: []\n",
		"empty listen":      "clients:\n  - listen: ''\n    server: example.com:443\n    password: secret\n",
		"duplicate listen":  "clients:\n  - listen: /tmp/anytls.sock\n    server: example.com:443\n    password: secret\n  - listen: /tmp/anytls.sock\n    server: example.org:443\n    password: secret\n",
		"invalid server":    "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com\n    password: secret\n",
		"empty password":    "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: ''\n",
		"negative min idle": "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: secret\n    min-idle: -1\n",
		"unknown field":     "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: secret\n    typo: value\n",
	}

	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := loadConfig(writeTestConfig(t, contents))
			assert.Error(t, err)
		})
	}
}

func TestLoadConfigRejectsMultipleDocuments(t *testing.T) {
	path := writeTestConfig(t, "clients:\n  - listen: 127.0.0.1:1080\n    server: example.com:443\n    password: secret\n---\nclients: []\n")

	_, err := loadConfig(path)
	assert.ErrorContains(t, err, "multiple YAML documents")
}

func TestListenUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.sock")
	listener, err := listen(path)
	if !assert.NoError(t, err) {
		return
	}
	t.Cleanup(func() { _ = listener.Close() })

	assert.Equal(t, "unix", listener.Addr().Network())
	conn, err := net.DialTimeout("unix", path, time.Second)
	if assert.NoError(t, err) {
		assert.NoError(t, conn.Close())
	}
}

func TestListenUnixUnlinksExistingSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if !assert.NoError(t, err) {
		return
	}
	stale.SetUnlinkOnClose(false)
	assert.NoError(t, stale.Close())

	listener, err := listen(path)
	if !assert.NoError(t, err) {
		return
	}
	t.Cleanup(func() { _ = listener.Close() })
	assertUnixDialSucceeds(t, path)
}

func TestListenUnixRefusesNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	contents := []byte("keep me")
	if !assert.NoError(t, os.WriteFile(path, contents, 0600)) {
		return
	}

	listener, err := listen(path)
	if assert.Error(t, err) {
		assert.Nil(t, listener)
	} else {
		_ = listener.Close()
	}
	got, readErr := os.ReadFile(path)
	if assert.NoError(t, readErr) {
		assert.Equal(t, contents, got)
	}
}

func TestReloadInvalidConfigLeavesListenersUntouched(t *testing.T) {
	path := writeTestConfig(t, testClientConfig("127.0.0.1:0", "first.example:443"))
	manager := newListenerManager(context.Background(), path, nil)
	if !assert.NoError(t, manager.start()) {
		return
	}
	t.Cleanup(func() { manager.active.retire() })

	active := manager.active
	address := active.listeners[0].listener.Addr().String()
	if !assert.NoError(t, os.WriteFile(path, []byte("clients: []\n"), 0600)) {
		return
	}
	assert.Error(t, manager.reload())
	assert.Same(t, active, manager.active)
	assertDialSucceeds(t, address)
}

func TestReloadReplacesListeners(t *testing.T) {
	oldAddress := freeTCPAddress(t)
	newAddress := freeTCPAddress(t)
	path := writeTestConfig(t, testClientConfig(oldAddress, "first.example:443"))
	manager := newListenerManager(context.Background(), path, nil)
	if !assert.NoError(t, manager.start()) {
		return
	}
	t.Cleanup(func() { manager.active.retire() })

	oldSet := manager.active
	if !assert.NoError(t, os.WriteFile(path, []byte(testClientConfig(newAddress, "second.example:443")), 0600)) {
		return
	}
	if !assert.NoError(t, manager.reload()) {
		return
	}
	assert.NotSame(t, oldSet, manager.active)
	assert.Equal(t, "second.example:443", manager.config.Clients[0].Server)
	assertDialFails(t, oldAddress)
	assertDialSucceeds(t, newAddress)
}

func TestReloadReusesUnchangedListenAddress(t *testing.T) {
	address := freeTCPAddress(t)
	path := writeTestConfig(t, testClientConfig(address, "first.example:443"))
	manager := newListenerManager(context.Background(), path, nil)
	if !assert.NoError(t, manager.start()) {
		return
	}
	t.Cleanup(func() { manager.active.retire() })

	oldListener := manager.active.listeners[0]
	oldSocket := oldListener.listener
	oldGeneration := oldListener.currentGeneration()
	if !assert.NoError(t, os.WriteFile(path, []byte(testClientConfig(address, "second.example:443")), 0600)) {
		return
	}
	if !assert.NoError(t, manager.reload()) {
		return
	}
	listener := manager.active.listeners[0]
	assert.Same(t, oldListener, listener)
	assert.Same(t, oldSocket, listener.listener)
	assert.NotSame(t, oldGeneration, listener.currentGeneration())
	assert.Equal(t, "second.example:443", listener.currentGeneration().config.Server)
	assertDialSucceeds(t, address)
}

func TestReloadReusesUnchangedUnixSocket(t *testing.T) {
	address := filepath.Join(t.TempDir(), "client.sock")
	path := writeTestConfig(t, testClientConfig(address, "first.example:443"))
	manager := newListenerManager(context.Background(), path, nil)
	if !assert.NoError(t, manager.start()) {
		return
	}
	t.Cleanup(func() { manager.active.retire() })

	oldListener := manager.active.listeners[0]
	oldSocket := oldListener.listener
	oldGeneration := oldListener.currentGeneration()
	if !assert.NoError(t, os.WriteFile(path, []byte(testClientConfig(address, "second.example:443")), 0600)) {
		return
	}
	if !assert.NoError(t, manager.reload()) {
		return
	}
	listener := manager.active.listeners[0]
	assert.Same(t, oldListener, listener)
	assert.Same(t, oldSocket, listener.listener)
	assert.NotSame(t, oldGeneration, listener.currentGeneration())
	assert.Equal(t, "second.example:443", listener.currentGeneration().config.Server)
	assertUnixDialSucceeds(t, address)
}

func TestReloadBindFailureDoesNotUpdateReusedListener(t *testing.T) {
	address := freeTCPAddress(t)
	path := writeTestConfig(t, testClientConfig(address, "first.example:443"))
	manager := newListenerManager(context.Background(), path, nil)
	if !assert.NoError(t, manager.start()) {
		return
	}
	t.Cleanup(func() { manager.active.retire() })

	active := manager.active
	listener := active.listeners[0]
	generation := listener.currentGeneration()
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	t.Cleanup(func() { _ = blocked.Close() })

	contents := testClientConfig(address, "second.example:443") + fmt.Sprintf("  - listen: %s\n    server: third.example:443\n    password: secret\n    min-idle: 0\n", blocked.Addr())
	if !assert.NoError(t, os.WriteFile(path, []byte(contents), 0600)) {
		return
	}
	assert.Error(t, manager.reload())
	assert.Same(t, active, manager.active)
	assert.Same(t, listener, manager.active.listeners[0])
	assert.Same(t, generation, listener.currentGeneration())
	assert.Equal(t, "first.example:443", listener.currentGeneration().config.Server)
	assertDialSucceeds(t, address)
}

func testClientConfig(listen, server string) string {
	return fmt.Sprintf("clients:\n  - listen: %s\n    server: %s\n    password: secret\n    min-idle: 0\n", listen, server)
}

func freeTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return ""
	}
	address := listener.Addr().String()
	assert.NoError(t, listener.Close())
	return address
}

func assertDialSucceeds(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if assert.NoError(t, err, "dial %s", address) {
		assert.NoError(t, conn.Close())
	}
}

func assertDialFails(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if !assert.Error(t, err, "dial to retired listener %s", address) {
		_ = conn.Close()
	}
}

func assertUnixDialSucceeds(t *testing.T, path string) {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if assert.NoError(t, err, "dial Unix socket %s", path) {
		assert.NoError(t, conn.Close())
	}
}

func writeTestConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	assert.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	return path
}
