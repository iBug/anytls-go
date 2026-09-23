package main

import (
	"anytls/proxy"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type config struct {
	Clients []clientConfig `yaml:"clients"`
}

type clientConfig struct {
	Listen       string `yaml:"listen"`
	Server       string `yaml:"server"`
	Password     string `yaml:"password"`
	SNI          string `yaml:"sni"`
	MinIdle      *int   `yaml:"min-idle"`
	DisableReuse bool   `yaml:"disable-reuse"`
}

func (c clientConfig) minIdle() int {
	if c.MinIdle == nil {
		return 5
	}
	return *c.MinIdle
}

type clientListener struct {
	listen   string
	listener net.Listener

	generationMu sync.Mutex
	generation   *clientGeneration
	acceptDone   chan struct{}
}

type clientGeneration struct {
	config      clientConfig
	client      *myClient
	connections sync.WaitGroup
}

type listenerSet struct {
	listeners []*clientListener
}

type listenerManager struct {
	ctx          context.Context
	configPath   string
	keyLogWriter io.Writer
	config       *config
	active       *listenerSet
	errCh        chan error
}

func loadConfig(path string) (*config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg config
	decoder := yaml.NewDecoder(f)
	decoder.KnownFields(true)
	if err = decoder.Decode(&cfg); err != nil {
		return nil, err
	}

	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple YAML documents are not supported")
		}
		return nil, err
	}

	if len(cfg.Clients) == 0 {
		return nil, fmt.Errorf("clients must contain at least one item")
	}
	listenAddresses := make(map[string]struct{}, len(cfg.Clients))
	for i := range cfg.Clients {
		client := &cfg.Clients[i]
		client.Listen = strings.TrimSpace(client.Listen)
		client.Server = strings.TrimSpace(client.Server)
		if client.Listen == "" {
			return nil, fmt.Errorf("clients[%d].listen must not be empty", i)
		}
		if _, exists := listenAddresses[client.Listen]; exists {
			return nil, fmt.Errorf("clients[%d].listen %q is duplicated", i, client.Listen)
		}
		listenAddresses[client.Listen] = struct{}{}
		if _, _, err = net.SplitHostPort(client.Server); err != nil {
			return nil, fmt.Errorf("clients[%d].server %q: %w", i, client.Server, err)
		}
		if client.Password == "" {
			return nil, fmt.Errorf("clients[%d].password must not be empty", i)
		}
		if client.minIdle() < 0 {
			return nil, fmt.Errorf("clients[%d].min-idle must not be negative", i)
		}
	}
	return &cfg, nil
}

func main() {
	configPath := flag.String("c", "", "path to client YAML config")
	flag.Parse()

	if *configPath == "" {
		logrus.Fatalln("please set -c config path")
	}

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	logrus.Infoln("[Client]", util.ProgramVersionName)

	var keyLogWriter io.Writer
	path := strings.TrimSpace(os.Getenv("TLS_KEY_LOG"))
	if path != "" {
		f, openErr := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if openErr != nil {
			logrus.Warnln("open TLS key log:", openErr)
		} else {
			defer f.Close()
			keyLogWriter = f
		}
	}

	ctx := context.Background()
	manager := newListenerManager(ctx, *configPath, keyLogWriter)
	if err = manager.start(); err != nil {
		logrus.Fatalln("start listeners:", err)
	}

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	defer signal.Stop(reloadCh)

	for {
		select {
		case <-reloadCh:
			if err = manager.reload(); err != nil {
				logrus.Warnln("reload config:", err)
			} else {
				logrus.Infoln("reloaded config:", *configPath)
			}
		case err = <-manager.errCh:
			logrus.Fatalln(err)
		}
	}
}

func newListenerManager(ctx context.Context, configPath string, keyLogWriter io.Writer) *listenerManager {
	return &listenerManager{
		ctx:          ctx,
		configPath:   configPath,
		keyLogWriter: keyLogWriter,
		errCh:        make(chan error, 1),
	}
}

func (m *listenerManager) start() error {
	cfg, err := loadConfig(m.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	listeners, err := openListenerSet(m.ctx, cfg, m.keyLogWriter, m.errCh)
	if err != nil {
		return err
	}
	m.config = cfg
	m.active = listeners
	return nil
}

func (m *listenerManager) reload() error {
	cfg, err := loadConfig(m.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	previous := make(map[string]*clientListener, len(m.active.listeners))
	for _, listener := range m.active.listeners {
		previous[listener.listen] = listener
	}

	next := &listenerSet{listeners: make([]*clientListener, 0, len(cfg.Clients))}
	newListeners := make([]*clientListener, 0, len(cfg.Clients))
	for _, clientCfg := range cfg.Clients {
		if listener, ok := previous[clientCfg.Listen]; ok {
			next.listeners = append(next.listeners, listener)
			delete(previous, clientCfg.Listen)
			continue
		}

		listener, openErr := newClientListener(m.ctx, clientCfg, m.keyLogWriter)
		if openErr != nil {
			for _, opened := range newListeners {
				opened.closeUnstarted()
			}
			return openErr
		}
		newListeners = append(newListeners, listener)
		next.listeners = append(next.listeners, listener)
	}

	for i, clientCfg := range cfg.Clients {
		listener := next.listeners[i]
		if listener.listen == clientCfg.Listen && !containsListener(newListeners, listener) {
			listener.update(newClientGeneration(m.ctx, clientCfg, m.keyLogWriter))
		}
	}
	for _, listener := range newListeners {
		go listener.serve(m.ctx, m.errCh)
		generation := listener.currentGeneration()
		logrus.Infoln("[Client] socks5/http", listener.listen, "=>", generation.config.Server)
	}
	for _, listener := range previous {
		listener.retire()
	}

	m.config = cfg
	m.active = next
	return nil
}

func openListenerSet(ctx context.Context, cfg *config, keyLogWriter io.Writer, errCh chan error) (*listenerSet, error) {
	set := &listenerSet{}
	for _, clientCfg := range cfg.Clients {
		listener, err := newClientListener(ctx, clientCfg, keyLogWriter)
		if err != nil {
			set.closeUnstarted()
			return nil, err
		}
		set.listeners = append(set.listeners, listener)
	}

	for _, listener := range set.listeners {
		go listener.serve(ctx, errCh)
		generation := listener.currentGeneration()
		logrus.Infoln("[Client] socks5/http", listener.listen, "=>", generation.config.Server)
	}
	return set, nil
}

func newClientListener(ctx context.Context, clientCfg clientConfig, keyLogWriter io.Writer) (*clientListener, error) {
	listener, err := listen(clientCfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", clientCfg.Listen, err)
	}
	return &clientListener{
		listen:     clientCfg.Listen,
		listener:   listener,
		generation: newClientGeneration(ctx, clientCfg, keyLogWriter),
		acceptDone: make(chan struct{}),
	}, nil
}

func listen(address string) (net.Listener, error) {
	if _, _, err := net.SplitHostPort(address); err == nil {
		return net.Listen("tcp", address)
	}

	info, err := os.Lstat(address)
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("path exists and is not a socket")
		}
		if err = os.Remove(address); err != nil {
			return nil, fmt.Errorf("unlink existing socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Unix socket path: %w", err)
	}

	listener, err := net.Listen("unix", address)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(address, 0666); err != nil {
		_ = listener.Close()
		_ = os.Remove(address)
		return nil, fmt.Errorf("set Unix socket permissions: %w", err)
	}
	return listener, nil
}

func newClientGeneration(ctx context.Context, clientCfg clientConfig, keyLogWriter io.Writer) *clientGeneration {
	return &clientGeneration{
		config: clientCfg,
		client: newConfiguredClient(ctx, clientCfg, keyLogWriter),
	}
}

func newConfiguredClient(ctx context.Context, clientCfg clientConfig, keyLogWriter io.Writer) *myClient {
	// InsecureSkipVerify is acceptable only in this sample client; it is not recommended for production code.
	tlsConfig := &tls.Config{
		ServerName:         clientCfg.SNI,
		InsecureSkipVerify: true,
		KeyLogWriter:       keyLogWriter,
	}
	if tlsConfig.ServerName == "" {
		// Disable SNI.
		tlsConfig.ServerName = "127.0.0.1"
	}

	passwordSha256 := sha256.Sum256([]byte(clientCfg.Password))
	client := NewMyClient(ctx, func(ctx context.Context) (net.Conn, error) {
		conn, err := proxy.SystemDialer.DialContext(ctx, "tcp", clientCfg.Server)
		if err != nil {
			return nil, err
		}
		return tls.Client(conn, tlsConfig), nil
	}, passwordSha256, clientCfg.minIdle(), clientCfg.DisableReuse)
	return client
}

func (l *clientListener) serve(ctx context.Context, errCh chan<- error) {
	defer close(l.acceptDone)
	for {
		c, err := l.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				select {
				case errCh <- fmt.Errorf("accept on %s: %w", l.listen, err):
				default:
				}
			}
			return
		}
		generation := l.acquireGeneration()
		go func() {
			defer generation.connections.Done()
			handleTcpConnection(ctx, c, generation.client)
		}()
	}
}

func (l *clientListener) acquireGeneration() *clientGeneration {
	l.generationMu.Lock()
	defer l.generationMu.Unlock()
	l.generation.connections.Add(1)
	return l.generation
}

func (l *clientListener) currentGeneration() *clientGeneration {
	l.generationMu.Lock()
	defer l.generationMu.Unlock()
	return l.generation
}

func (l *clientListener) update(generation *clientGeneration) {
	l.generationMu.Lock()
	previous := l.generation
	l.generation = generation
	l.generationMu.Unlock()
	closeGenerationWhenIdle(previous)
}

func (l *clientListener) retire() {
	_ = l.listener.Close()
	go func() {
		<-l.acceptDone
		closeGenerationWhenIdle(l.currentGeneration())
	}()
}

func (l *clientListener) closeUnstarted() {
	_ = l.listener.Close()
	_ = l.currentGeneration().client.Close()
}

func closeGenerationWhenIdle(generation *clientGeneration) {
	go func() {
		generation.connections.Wait()
		_ = generation.client.Close()
	}()
}

func containsListener(listeners []*clientListener, target *clientListener) bool {
	for _, listener := range listeners {
		if listener == target {
			return true
		}
	}
	return false
}

func (s *listenerSet) retire() {
	for _, listener := range s.listeners {
		listener.retire()
	}
}

func (s *listenerSet) closeUnstarted() {
	for _, listener := range s.listeners {
		listener.closeUnstarted()
	}
}
