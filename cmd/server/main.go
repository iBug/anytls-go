package main

import (
	"anytls/proxy/padding"
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

var passwordHashes atomic.Value

type passwordFile struct {
	Passwords []string `json:"passwords"`
}

func loadPasswordHashes(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		logrus.Errorln("open password file:", err)
		return false
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		logrus.Errorln("read password file:", err)
		return false
	}
	var pf passwordFile
	if err = json.Unmarshal(b, &pf); err != nil {
		logrus.Errorln("parse password file:", err)
		return false
	}
	if len(pf.Passwords) == 0 {
		logrus.Errorln("password file has no passwords")
		return false
	}
	hashes := make([][32]byte, 0, len(pf.Passwords))
	for _, password := range pf.Passwords {
		hashes = append(hashes, sha256.Sum256([]byte(password)))
	}
	passwordHashes.Store(hashes)
	return true
}

func main() {
	listen := flag.String("l", "0.0.0.0:8443", "server listen port")
	passwordFilePath := flag.String("p", "", `path to password json file: {"passwords":["password1","password2"]}`)
	paddingScheme := flag.String("padding-scheme", "", "padding-scheme")
	flag.Parse()

	if *passwordFilePath == "" {
		logrus.Fatalln("please set password file path")
	}
	if *paddingScheme != "" {
		if f, err := os.Open(*paddingScheme); err == nil {
			b, err := io.ReadAll(f)
			if err != nil {
				logrus.Fatalln(err)
			}
			if padding.UpdatePaddingScheme(b) {
				logrus.Infoln("loaded padding scheme file:", *paddingScheme)
			} else {
				logrus.Errorln("wrong format padding scheme file:", *paddingScheme)
			}
			f.Close()
		} else {
			logrus.Fatalln(err)
		}
	}

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	if !loadPasswordHashes(*passwordFilePath) {
		logrus.Fatalln("failed to load password file")
	}
	logrus.Infoln("loaded password file:", *passwordFilePath)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	go func() {
		for range sigCh {
			if loadPasswordHashes(*passwordFilePath) {
				logrus.Infoln("reloaded password file:", *passwordFilePath)
			} else {
				logrus.Errorln("failed to reload password file:", *passwordFilePath)
			}
		}
	}()

	logrus.Infoln("[Server]", util.ProgramVersionName)
	logrus.Infoln("[Server] Listening TCP", *listen)

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logrus.Fatalln("listen server tcp:", err)
	}

	tlsCert, _ := util.GenerateKeyPair(time.Now, "")
	tlsConfig := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return tlsCert, nil
		},
	}

	ctx := context.Background()
	server := NewMyServer(tlsConfig)

	for {
		c, err := listener.Accept()
		if err != nil {
			logrus.Fatalln("accept:", err)
		}
		go handleTcpConnection(ctx, c, server)
	}
}
