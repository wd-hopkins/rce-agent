// Copyright 2017-2023 Block, Inc.

package rce_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/wd-hopkins/rce-agent"
	"github.com/wd-hopkins/rce-agent/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestClientExitZero(t *testing.T) {
	s := rce.NewServer(LADDR, nil, whitelist)
	go s.StartServer()
	defer s.StopServer()

	time.Sleep(200 * time.Millisecond)

	c := rce.NewClient(nil)
	err := c.Open(HOST, PORT)
	if err != nil {
		t.Fatal(err)
	}

	id, err := c.Start("exit.zero", []string{})
	if err != nil {
		t.Error(err)
	}

	status, err := c.Wait(id)
	if err != nil {
		t.Error(err)
	}

	if status.ExitCode != 0 {
		t.Errorf("got exit %d, expected 0", status.ExitCode)
	}
}

func TestClientLongRunningCommand(t *testing.T) {
	s := rce.NewServer(LADDR, nil, whitelist)
	go s.StartServer()
	defer s.StopServer()

	time.Sleep(200 * time.Millisecond)

	c := rce.NewClient(nil)
	err := c.Open(HOST, PORT)
	if err != nil {
		t.Fatal(err)
	}

	id, err := c.Start("sleep60", []string{})
	if err != nil {
		t.Error(err)
	}

	doneChan := make(chan struct{})
	var finalStatus *pb.Status
	var waitErr error
	go func() {
		defer close(doneChan)
		finalStatus, waitErr = c.Wait(id)
	}()

	time.Sleep(1 * time.Second)
	gotRunning, err := c.Running()
	if err != nil {
		t.Error(err)
	}
	expectRunning := []string{id}
	if diff := deep.Equal(gotRunning, expectRunning); diff != nil {
		t.Error(diff)
	}

	runningStatus, err := c.GetStatus(id)
	if err != nil {
		t.Error(err)
	}
	if runningStatus.State != pb.STATE_RUNNING {
		t.Errorf("Status.State = %d, expected %d (RUNNING)", runningStatus.State, pb.STATE_RUNNING)
	}

	err = c.Stop(id)
	if err != nil {
		t.Error(err)
	}

	select {
	case <-doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for command to stop")
	}

	if waitErr != nil {
		t.Error(waitErr)
	}
	if finalStatus.ExitCode != -1 {
		t.Errorf("got exit %d, expected -1", finalStatus.ExitCode)
	}
}

func TestClientExecLongRunningCommand(t *testing.T) {
	s := rce.NewServer(LADDR, nil, whitelist)
	go s.StartServer()
	defer s.StopServer()

	time.Sleep(200 * time.Millisecond)

	c := rce.NewClient(nil)
	err := c.Open(HOST, PORT)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// echo-loop prints "tick" every 200ms for 2 seconds (10 iterations).
	cmd := &pb.Command{
		Name:      "echo-loop",
		Arguments: []string{},
	}

	stream, err := c.Exec(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}

	var lastStatus *pb.Status
	var firstStdoutAt, lastStdoutAt time.Time
	for {
		st, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range st.Stdout {
			now := time.Now()
			if firstStdoutAt.IsZero() {
				firstStdoutAt = now
			}
			lastStdoutAt = now
			fmt.Fprintf(os.Stdout, "%s %s\n", now.Format(time.RFC3339Nano), line)
		}
		lastStatus = st
	}

	// Verify that stdout frames were streamed in real time rather than all
	// delivered at once after the command finished. The echo-loop emits a line
	// every 200ms for 2 seconds, so the spread between the first and last
	// received stdout frame must be at least 1 second.
	if spread := lastStdoutAt.Sub(firstStdoutAt); spread < time.Second {
		t.Errorf("stdout frames were not streamed in real time: spread between first and last frame was %v, expected at least 1s", spread)
	}

	if lastStatus == nil {
		t.Fatal("received no frames from exec stream")
	}
	if lastStatus.ExitCode != 0 {
		t.Errorf("last frame ExitCode = %d, expected 0", lastStatus.ExitCode)
	}
}

// startAuthServer starts a server that requires the given bearer token.
// The env var is consumed by NewServer, so this helper sets it immediately
// before construction to keep each test self-contained.
func startAuthServer(t *testing.T, token string) rce.Server {
	t.Helper()
	os.Setenv("RCE_AUTH_TOKEN", token)
	s := rce.NewServer(LADDR, nil, whitelist)
	// Verify the secret was cleared from the environment immediately.
	if got := os.Getenv("RCE_AUTH_TOKEN"); got != "" {
		t.Errorf("RCE_AUTH_TOKEN still set after NewServer; child processes would inherit the secret")
	}
	go s.StartServer()
	time.Sleep(200 * time.Millisecond)
	return s
}

// TestAuthMissingToken verifies that a client without a token is rejected.
func TestAuthMissingToken(t *testing.T) {
	s := startAuthServer(t, "supersecret")
	defer s.StopServer()

	c := rce.NewClient(nil) // no token set
	if err := c.Open(HOST, PORT); err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, err := c.Start("exit.zero", []string{})
	if err == nil {
		t.Fatal("expected Unauthenticated error, got nil")
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got gRPC code %v, expected Unauthenticated", code)
	}
}

// TestAuthWrongToken verifies that a client with an incorrect token is rejected.
func TestAuthWrongToken(t *testing.T) {
	s := startAuthServer(t, "supersecret")
	defer s.StopServer()

	c := rce.NewClient(nil)
	c.SetToken("wrongtoken")
	if err := c.Open(HOST, PORT); err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, err := c.Start("exit.zero", []string{})
	if err == nil {
		t.Fatal("expected Unauthenticated error, got nil")
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got gRPC code %v, expected Unauthenticated", code)
	}
}

// TestAuthValidToken verifies that a client with the correct token succeeds.
func TestAuthValidToken(t *testing.T) {
	const token = "supersecret"
	s := startAuthServer(t, token)
	defer s.StopServer()

	c := rce.NewClient(nil)
	c.SetToken(token)
	if err := c.Open(HOST, PORT); err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	id, err := c.Start("exit.zero", []string{})
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Wait(id)
	if err != nil {
		t.Fatal(err)
	}
	if st.ExitCode != 0 {
		t.Errorf("ExitCode = %d, expected 0", st.ExitCode)
	}
}

// TestAuthExecMissingToken verifies that the streaming Exec RPC is also protected.
func TestAuthExecMissingToken(t *testing.T) {
	s := startAuthServer(t, "supersecret")
	defer s.StopServer()

	c := rce.NewClient(nil) // no token
	if err := c.Open(HOST, PORT); err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	stream, err := c.Exec(context.Background(), &pb.Command{Name: "exit.zero"})
	if err != nil {
		// Some gRPC versions surface auth errors here rather than on Recv.
		if code := status.Code(err); code != codes.Unauthenticated {
			t.Errorf("got gRPC code %v, expected Unauthenticated", code)
		}
		return
	}
	_, err = stream.Recv()
	if err == nil {
		t.Fatal("expected Unauthenticated error from Recv, got nil")
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got gRPC code %v, expected Unauthenticated", code)
	}
}
