/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package rawlink_test

import (
	"errors"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"

	"github.com/farsightsec/sielink"
	"github.com/farsightsec/sielink/rawlink"

	"golang.org/x/net/websocket"

	"net/http"
)

var server = "localhost:8765"
var serverURL = "ws://" + server

var clientURL = "ws://localhost:4321/client"

func testDial(l *rawlink.Link, URL string) error {
	conn, err := websocket.Dial(URL, "", clientURL)
	if err != nil {
		return err
	}
	return l.HandleConnection(conn)
}

type testLink struct {
	clientWg, serverWg     sync.WaitGroup
	clientLink, serverLink *rawlink.Link
	serverURL              string
}

func newTestLink(t *testing.T, name string, nconn int) *testLink {
	path := "/" + name
	tl := &testLink{
		clientLink: rawlink.NewLink(),
		serverLink: rawlink.NewLink(),
		serverURL:  serverURL + path,
	}

	tl.clientWg.Add(nconn)
	tl.serverWg.Add(nconn)
	http.Handle(path, websocket.Handler(
		func(c *websocket.Conn) {
			tl.clientWg.Done()
			tl.serverLink.HandleConnection(c)
			tl.serverWg.Done()
		}))

	for i := 0; i < nconn; i++ {
		go func() {
			if err := testDial(tl.clientLink, tl.serverURL); err != nil {
				t.Log(err)
				tl.clientWg.Done()
				tl.serverWg.Done()
			}
		}()
	}

	if err := waitFor(time.Second, tl.clientWg.Wait); err != nil {
		t.Fatal(err)
	}
	<-time.After(time.Millisecond)

	return tl
}

func waitFor(t time.Duration, f func()) error {
	ch := make(chan struct{})
	go func() {
		f()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(t):
		return errors.New("Timed out")
	}
	return nil
}

func init() {
	go func() {
		log.Fatal(http.ListenAndServe(server, nil))
	}()
}

// Set up multi-connection Link, signal remote to call Link.Close(),
// verify that connections are closed.
func TestLinkClose(t *testing.T) {
	tl := newTestLink(t, "TestLinkClose", 5)

	tl.clientLink.Close()
	if err := waitFor(time.Second, tl.serverWg.Wait); err != nil {
		t.Error(err)
	}
	t.Log("connection close finished")
}

// Send Finish on link, verify that remote Receive() channel returns.
func TestLinkFinish(t *testing.T) {
	tl := newTestLink(t, "TestLinkFinish", 5)
	tl.clientLink.Finish()
	err := waitFor(time.Second, func() {
		tl.serverLink.Shutdown()
		<-tl.serverLink.Receive()
		tl.serverLink.Finish()
	})
	if err != nil {
		t.Error(err)
	}
	err = waitFor(time.Second, func() {
		<-tl.clientLink.Receive()
		tl.clientLink.Close()
	})
	if err != nil {
		t.Error(err)
	}
}

// Send Shutdown on link, verify that remote Finishes (local Receive() channel
// should return)
func TestLinkShutdown(t *testing.T) {
	tl := newTestLink(t, "TestLinkShutdown", 5)
	tl.clientLink.Shutdown()
	err := waitFor(time.Second, func() {
		<-tl.clientLink.Receive()
	})
	if err != nil {
		t.Error(err)
	}
	tl.clientLink.Close()
}

// Use SetSubscription and SetPath to trigger sending of control messages.
// Verify that control messages are sent to ControlFunc
// Verify that connection exit is reported to ControlFunc (m == nil)
func TestLinkControlMessage(t *testing.T) {
	nconn := 5
	tl := newTestLink(t, "TestLinkControlMessage", nconn)
	var swg, cwg sync.WaitGroup
	var scwg, ccwg sync.WaitGroup
	swg.Add(nconn)
	cwg.Add(nconn)
	scwg.Add(nconn)
	ccwg.Add(nconn)
	tl.serverLink.TopologyFunc = func(c *websocket.Conn, m *sielink.Topology) {
		t.Log("ServerLink: ", m)
		if m == nil {
			swg.Done()
			return
		}
		scwg.Done()
	}

	tl.clientLink.TopologyFunc = func(c *websocket.Conn, m *sielink.Topology) {
		t.Log("ClientLink: ", m)
		if m == nil {
			cwg.Done()
			return
		}
		ccwg.Done()
	}

	t.Log("clientLink.SetSubscription")
	tl.clientLink.SetSubscription([]*sielink.Subscription{
		&sielink.Subscription{Channel: []uint32{5}},
	})
	if err := waitFor(time.Second, scwg.Wait); err != nil {
		t.Error(err)
	}
	t.Log("serverLink.SetPath")
	tl.serverLink.SetPath([]*sielink.Path{
		&sielink.Path{Metric: proto.Uint64(1000), Site: []uint32{5}},
	})
	if err := waitFor(time.Second, ccwg.Wait); err != nil {
		t.Error(err)
	}
	t.Log("clientLink.Finish")
	tl.clientLink.Finish()
	if err := waitFor(time.Second, swg.Wait); err != nil {
		t.Error(err)
	}
	t.Log("serverLink.Finish")
	tl.serverLink.Finish()
	if err := waitFor(time.Second, cwg.Wait); err != nil {
		t.Error(err)
	}
}

// Respond with alert message, verify client connection returns error.
func TestLinkAlert(t *testing.T) {
	alert := &sielink.Alert{
		Level:   sielink.AlertLevel_FatalError.Enum(),
		Message: proto.String("Test Alert"),
	}
	http.Handle("/TestLinkAlert", websocket.Handler(
		func(c *websocket.Conn) {
			m := &sielink.Message{
				ProtocolVersion: sielink.SupportedVersions,
				MessageType:     sielink.MessageType_AlertMessage.Enum(),
				Alert:           alert,
			}
			b, err := proto.Marshal(m)
			if err != nil {
				return
			}
			websocket.Message.Send(c, b)
			websocket.Message.Receive(c, m)
		}))
	cl := rawlink.NewLink()

	err := waitFor(time.Second, func() {
		t.Log(testDial(cl, serverURL+"/TestLinkAlert"))
	})
	if err != nil {
		t.Error(err)
	}
}

// Respond with unsupported version. Verify client connection returns error.
func TestLinkVersion(t *testing.T) {
	http.Handle("/TestLinkVersion", websocket.Handler(
		func(c *websocket.Conn) {
			m := &sielink.Message{
				ProtocolVersion: []uint32{0},
				MessageType:     sielink.MessageType_TopologyMessage.Enum(),
			}
			b, err := proto.Marshal(m)
			if err != nil {
				return
			}
			websocket.Message.Send(c, b)
			websocket.Message.Receive(c, m)
		}))

	cl := rawlink.NewLink()

	err := waitFor(time.Second, func() {
		t.Log(testDial(cl, serverURL+"/TestLinkVersion"))
	})
	if err != nil {
		t.Error(err)
	}

}
