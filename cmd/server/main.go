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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

var userByPasswordHash atomic.Value
var activeConnectionUser sync.Map

type usersFile struct {
	Users map[string]string `json:"users"`
}

func loadUsers(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		logrus.Errorln("open users file:", err)
		return false
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		logrus.Errorln("read users file:", err)
		return false
	}
	var uf usersFile
	if err = json.Unmarshal(b, &uf); err != nil {
		logrus.Errorln("parse users file:", err)
		return false
	}
	if len(uf.Users) == 0 {
		logrus.Errorln("users file has no users")
		return false
	}
	hashes := make(map[[32]byte]string, len(uf.Users))
	for user, password := range uf.Users {
		hashes[sha256.Sum256([]byte(password))] = user
	}
	userByPasswordHash.Store(hashes)
	return true
}

func main() {
	listen := flag.String("l", "0.0.0.0:8443", "server listen port")
	usersFilePath := flag.String("p", "", `path to users json file: {"users":{"user1":"password1","user2":"password2"}}`)
	paddingScheme := flag.String("padding-scheme", "", "padding-scheme")
	flag.Parse()

	if *usersFilePath == "" {
		logrus.Fatalln("please set users file path")
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

	if !loadUsers(*usersFilePath) {
		logrus.Fatalln("failed to load users file")
	}
	logrus.Infoln("loaded users file:", *usersFilePath)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	go func() {
		for range sigCh {
			if loadUsers(*usersFilePath) {
				logrus.Infoln("reloaded users file:", *usersFilePath)
			} else {
				logrus.Errorln("failed to reload users file:", *usersFilePath)
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
