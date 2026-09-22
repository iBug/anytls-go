package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"anytls/util"
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type myClient struct {
	dialOut        util.DialOutFunc
	passwordSha256 [32]byte
	sessionClient  *session.Client
}

func NewMyClient(ctx context.Context, dialOut util.DialOutFunc, passwordSha256 [32]byte, minIdleSession int, disableReuse bool) *myClient {
	s := &myClient{
		dialOut:        dialOut,
		passwordSha256: passwordSha256,
	}
	s.sessionClient = session.NewClient(ctx, s.createOutboundConnection, &padding.DefaultPaddingFactory, time.Second*30, time.Second*30, minIdleSession, disableReuse)
	return s
}

func (c *myClient) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *myClient) Close() error {
	return c.sessionClient.Close()
}

func (c *myClient) createOutboundConnection(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	b := buf.NewPacket()
	defer b.Release()

	b.Write(c.passwordSha256[:])
	var paddingLen int
	if pad := padding.DefaultPaddingFactory.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}

	_, err = b.WriteTo(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}
