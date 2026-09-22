package main

import (
	"anytls/proxy"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type config struct {
	Clients []clientConfig `yaml:"clients"`
}

type clientConfig struct {
	Listen   string `yaml:"listen"`
	Server   string `yaml:"server"`
	Password string `yaml:"password"`
}

type configuredListener struct {
	config   clientConfig
	listener net.Listener
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
	}
	return &cfg, nil
}

func main() {
	configPath := flag.String("c", "", "path to client YAML config")
	sni := flag.String("sni", "", "Server Name Indication")
	minIdleSession := flag.Int("m", 5, "Reserved min idle session")
	disableReuse := flag.Bool("dr", false, "Disable client session reuse")
	flag.Parse()

	if *configPath == "" {
		logrus.Fatalln("please set -c config path")
	}

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		logrus.Fatalln("load config:", err)
	}

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

	listeners := make([]configuredListener, 0, len(cfg.Clients))
	for _, clientCfg := range cfg.Clients {
		listener, listenErr := net.Listen("tcp", clientCfg.Listen)
		if listenErr != nil {
			for _, opened := range listeners {
				_ = opened.listener.Close()
			}
			logrus.Fatalln("listen socks5/http tcp:", clientCfg.Listen, listenErr)
		}
		listeners = append(listeners, configuredListener{config: clientCfg, listener: listener})
	}

	ctx := context.Background()
	errCh := make(chan error, len(listeners))
	for _, configured := range listeners {
		go serveClient(ctx, configured, *sni, keyLogWriter, *minIdleSession, *disableReuse, errCh)
	}
	logrus.Fatalln(<-errCh)
}

func serveClient(ctx context.Context, configured configuredListener, sni string, keyLogWriter io.Writer, minIdleSession int, disableReuse bool, errCh chan<- error) {
	clientCfg := configured.config
	// InsecureSkipVerify is acceptable only in this sample client; it is not recommended for production code.
	tlsConfig := &tls.Config{
		ServerName:         sni,
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
	}, passwordSha256, minIdleSession, disableReuse)

	logrus.Infoln("[Client] socks5/http", clientCfg.Listen, "=>", clientCfg.Server)
	for {
		c, err := configured.listener.Accept()
		if err != nil {
			errCh <- fmt.Errorf("accept on %s: %w", clientCfg.Listen, err)
			return
		}
		go handleTcpConnection(ctx, c, client)
	}
}
