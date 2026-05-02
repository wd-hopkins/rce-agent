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
