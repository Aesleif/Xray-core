package nidhogg

import (
	"context"
	"fmt"

	"github.com/aesleif/nidhogg/pkg/nidhogg"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Client is the outbound handler for the nidhogg protocol.
type Client struct {
	nidhoggClient *nidhogg.Client
}

// NewClient creates a nidhogg outbound handler from protobuf config.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	addr := fmt.Sprintf("%s:%d", config.ServerAddress, config.ServerPort)

	mode, err := nidhogg.ParseShapingMode(config.ShapingMode)
	if err != nil {
		return nil, errors.New("invalid shaping mode: ", config.ShapingMode).Base(err)
	}

	c, err := nidhogg.NewClient(nidhogg.ClientConfig{
		Server:      addr,
		PSK:         config.Psk,
		TunnelPath:  config.TunnelPath,
		Fingerprint: config.Fingerprint,
		ShapingMode: mode,
		Insecure:    config.Insecure,
	})
	if err != nil {
		return nil, errors.New("failed to create nidhogg client").Base(err)
	}

	return &Client{nidhoggClient: c}, nil
}

// Process implements proxy.Outbound.
func (c *Client) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "nidhogg"
	destination := ob.Target

	dest := destination.NetAddr() // "host:port"
	if destination.Network == net.Network_UDP {
		dest = "udp:" + dest
	}

	conn, err := c.nidhoggClient.Dial(ctx, dest)
	if err != nil {
		return errors.New("failed to dial nidhogg tunnel to ", dest).Base(err)
	}
	defer conn.Close()

	errors.LogInfo(ctx, "nidhogg tunnel opened to ", dest,
		", profile=", conn.Profile().Name,
		", rtt=", conn.HandshakeRTT())

	var requestWriter buf.Writer
	var responseReader buf.Reader
	if destination.Network == net.Network_UDP {
		requestWriter = &PacketWriter{Writer: conn, Target: destination}
		responseReader = &PacketReader{Reader: conn, Target: destination}
	} else {
		requestWriter = buf.NewWriter(conn)
		responseReader = buf.NewReader(conn)
	}

	requestDone := func() error {
		return buf.Copy(link.Reader, requestWriter)
	}

	responseDone := func() error {
		return buf.Copy(responseReader, link.Writer)
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(link.Writer))); err != nil {
		return errors.New("nidhogg connection ended").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
