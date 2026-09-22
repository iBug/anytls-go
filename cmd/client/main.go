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
	config   clientConfig
	listener net.Listener
	client   *myClient

	connections sync.WaitGroup
	acceptDone  chan struct{}
}

type listenerSet struct {
	listeners []*clientListener
	errCh     chan error
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
	for i := range cfg.Clients {
		client := &cfg.Clients[i]
		client.Listen = strings.TrimSpace(client.Listen)
		client.Server = strings.TrimSpace(client.Server)
		if _, _, err = net.SplitHostPort(client.Listen); err != nil {
			return nil, fmt.Errorf("clients[%d].listen %q: %w", i, client.Listen, err)
		}
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

	previousConfig := m.config
	m.active.retire()
	listeners, err := openListenerSet(m.ctx, cfg, m.keyLogWriter, m.errCh)
	if err != nil {
		restored, restoreErr := openListenerSet(m.ctx, previousConfig, m.keyLogWriter, m.errCh)
		if restoreErr != nil {
			m.active = nil
			return fmt.Errorf("open new listeners: %w; restore previous listeners: %v", err, restoreErr)
		}
		m.active = restored
		return fmt.Errorf("open new listeners: %w; restored previous listeners", err)
	}

	m.config = cfg
	m.active = listeners
	return nil
}

func openListenerSet(ctx context.Context, cfg *config, keyLogWriter io.Writer, errCh chan error) (*listenerSet, error) {
	set := &listenerSet{errCh: errCh}
	for _, clientCfg := range cfg.Clients {
		listener, err := net.Listen("tcp", clientCfg.Listen)
		if err != nil {
			set.closeUnstarted()
			return nil, fmt.Errorf("listen on %s: %w", clientCfg.Listen, err)
		}
		set.listeners = append(set.listeners, &clientListener{
			config:     clientCfg,
			listener:   listener,
			acceptDone: make(chan struct{}),
		})
	}

	for _, listener := range set.listeners {
		listener.client = newConfiguredClient(ctx, listener.config, keyLogWriter)
		go listener.serve(ctx, set.errCh)
		logrus.Infoln("[Client] socks5/http", listener.config.Listen, "=>", listener.config.Server)
	}
	return set, nil
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
				case errCh <- fmt.Errorf("accept on %s: %w", l.config.Listen, err):
				default:
				}
			}
			return
		}
		l.connections.Add(1)
		go func() {
			defer l.connections.Done()
			handleTcpConnection(ctx, c, l.client)
		}()
	}
}

func (s *listenerSet) retire() {
	for _, listener := range s.listeners {
		_ = listener.listener.Close()
	}
	for _, listener := range s.listeners {
		go func() {
			<-listener.acceptDone
			listener.connections.Wait()
			_ = listener.client.Close()
		}()
	}
}

func (s *listenerSet) closeUnstarted() {
	for _, listener := range s.listeners {
		_ = listener.listener.Close()
	}
}
