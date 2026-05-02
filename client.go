// Copyright 2017-2023 Block, Inc.

// Package rce provides a gRPC-based Remote Code Execution client and server.
// The server (or "agent") runs on a remote host and executes a whitelist of
// shell commands specified in a config file. The client calls the server to
// execute whitelist commands. Commands from different clients run concurrently;
// there are no safeguards against conflicting or incompatible commands.
package rce

import (
	"crypto/tls"
	"io"
	"time"

	"github.com/wd-hopkins/rce-agent/pb"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// tokenCreds implements credentials.PerRPCCredentials for bearer token auth.
type tokenCreds struct{ token string }

func (t tokenCreds) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"Authorization": "Bearer " + t.token}, nil
}

func (t tokenCreds) RequireTransportSecurity() bool { return false }

var (
	// KeepaliveTime is the interval at which the client sends keepalive
	// probes to the server.
	KeepaliveTime = time.Duration(30) * time.Second

	// KeepaliveTimeout is the amount of time the client waits to receive
	// a response from the server after a keepalive probe.
	KeepaliveTimeout = time.Duration(20) * time.Second
)

// ExecStream is returned by Client.Exec and delivers a stream of Status frames
// from a running command. Callers must drain it until io.EOF or an error.
type ExecStream interface {
	Recv() (*pb.Status, error)
}

// A Client calls a remote agent (server) to execute commands.
type Client interface {
	// Open Connect to a remote agent.
	Open(host, port string) error

	// Close connection to a remote agent.
	Close() error

	// AgentAddr Return hostname and port of remote agent, if connected.
	AgentAddr() (string, string)

	// Start a command on the remote agent. Must be connected first by calling
	// Connect. This call is non-blocking. It returns the ID of the command or
	// an error.
	Start(cmdName string, args []string) (id string, err error)

	// Wait for a command on the remote agent. This call blocks until the command
	// completes. It returns the final statue of the command or an error.
	Wait(id string) (*pb.Status, error)

	// GetStatus Get the status of a running command. This is safe to call by multiple
	// goroutines. ErrNotFound is returned if Wait or Stop has already been
	// called.
	GetStatus(id string) (*pb.Status, error)

	// Stop a running command. ErrNotFound is returne if Wait or Stop has already
	// been called.
	Stop(id string) error

	// Running Return a list of all running command IDs.
	Running() ([]string, error)

	// Exec Execute a command on the remote agent and stream its status frames.
	// The returned ExecStream must be drained until io.EOF or an error.
	Exec(ctx context.Context, cmd *pb.Command) (ExecStream, error)

	// SetToken configures a bearer token that is attached to every RPC as an
	// Authorization header. Must be called before Open.
	SetToken(token string)
}

type client struct {
	host      string
	port      string
	conn      *grpc.ClientConn
	agent     pb.RCEAgentClient
	tlsConfig *tls.Config
	token     string
}

// NewClient makes a new Client.
func NewClient(tlsConfig *tls.Config) Client {
	return &client{tlsConfig: tlsConfig}
}

func (c *client) SetToken(token string) {
	c.token = token
}

func (c *client) Open(host, port string) error {
	var opts []grpc.DialOption
	if c.tlsConfig == nil {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		creds := credentials.NewTLS(c.tlsConfig)
		err := creds.OverrideServerName(host)
		if err != nil {
			return err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}
	if c.token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(tokenCreds{c.token}))
	}

	opts = append(opts,
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    KeepaliveTime,
			Timeout: KeepaliveTimeout,
		}),
	)
	conn, err := grpc.NewClient(host+":"+port, opts...)
	if err != nil {
		return err
	}
	c.conn = conn
	c.agent = pb.NewRCEAgentClient(conn)
	c.host = host
	c.port = port
	return nil
}

func (c *client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *client) AgentAddr() (string, string) {
	return c.host, c.port
}

func (c *client) Start(cmdName string, args []string) (string, error) {
	cmd := &pb.Command{
		Name:      cmdName,
		Arguments: args,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	id, err := c.agent.Start(ctx, cmd)
	if err != nil {
		return "", err
	}

	return id.ID, nil
}

func (c *client) Wait(id string) (*pb.Status, error) {
	return c.agent.Wait(context.TODO(), &pb.ID{ID: id})
}

func (c *client) GetStatus(id string) (*pb.Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return c.agent.GetStatus(ctx, &pb.ID{ID: id})
}

func (c *client) Stop(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := c.agent.Stop(ctx, &pb.ID{ID: id})
	return err
}

func (c *client) Running() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	stream, err := c.agent.Running(ctx, &pb.Empty{})
	if err != nil {
		return nil, err
	}

	var ids []string
	for {
		id, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		ids = append(ids, id.ID)
	}

	return ids, nil
}

func (c *client) Exec(ctx context.Context, cmd *pb.Command) (ExecStream, error) {
	return c.agent.Exec(ctx, cmd)
}
