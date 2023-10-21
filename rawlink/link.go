/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// Package rawlink implements the base sielink Link protocol. It is not intended
// to be used directly, but different usage profiles of the Link protocol may embed
// a Link instance and implement their operations on top of it.
package rawlink

import (
	"errors"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/farsightsec/sielink"
)

// Link is the basic sielink protocol engine on which usage profiles (e.g.
// sielink.Client) may be built.
type Link struct {
	mutex            sync.Mutex
	configMessage    *sielink.Message
	configUpdate     chan struct{}
	readWg           sync.WaitGroup
	err              error
	shutdown, closed chan struct{}

	recvPayload, sendPayload chan *sielink.Payload

	// Heartbeat specifies the interval between heartbeat messages
	// sent on link connections. The Link attempts to send a heartbeat
	Heartbeat time.Duration

	// TopologyFunc receives all topology messages received on the
	// link. It is called with a nil topology when a connection closes.
	TopologyFunc func(c *websocket.Conn, t *sielink.Topology)

	// AlertFunc receives all non-fatal alerts received on the link.
	AlertFunc func(c *websocket.Conn, a *sielink.Alert)
}

// NewLink creates a raw Link with the given configuration.
func NewLink() *Link {
	return &Link{
		configMessage: newConfigMessage(nil, nil, nil),
		configUpdate:  make(chan struct{}),
		shutdown:      make(chan struct{}),
		closed:        make(chan struct{}),
		recvPayload:   make(chan *sielink.Payload, 100),
		sendPayload:   make(chan *sielink.Payload),
		TopologyFunc:  func(c *websocket.Conn, t *sielink.Topology) {},
		AlertFunc:     func(c *websocket.Conn, a *sielink.Alert) {},
	}
}

var (
	errLinkClosed   = errors.New("Link is closed")
	errLinkShutdown = errors.New("Link is shut down")
	errLinkFinished = errors.New("Link is finished sending")
)

// SetSubscription sets the channel subscriptions requested from peers
// connected to the Link.
func (l *Link) SetSubscription(subs []*sielink.Subscription) {
	subc := make([]*sielink.Subscription, len(subs))
	copy(subc, subs)

	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.configMessage = newConfigMessage(subs, l.configMessage.Topology.Path, l.configMessage.Heartbeat)
	close(l.configUpdate)
	l.configUpdate = make(chan struct{})
}

// SetPath sets the paths advertised to peers connected to the
// Link.
func (l *Link) SetPath(paths []*sielink.Path) {
	pathc := make([]*sielink.Path, len(paths))
	copy(pathc, paths)

	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.configMessage = newConfigMessage(l.configMessage.Topology.Subscription, paths, l.configMessage.Heartbeat)
	close(l.configUpdate)
	l.configUpdate = make(chan struct{})
}

// Receive returns a channel on which incoming data is presented.
func (l *Link) Receive() <-chan *sielink.Payload {
	return l.recvPayload
}

// Send sends a payload on an available connection.
func (l *Link) Send(p *sielink.Payload) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if err != nil {
				err = l.err
				return
			}
			err = errLinkClosed
		}
	}()
	l.sendPayload <- p
	return
}

func (l *Link) closeReader() {
	defer func() { recover() }()
	l.readWg.Wait()
	close(l.recvPayload)
}

// Close instructs the Link to close all connections.
func (l *Link) Close() (err error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	err = l.err
	l.err = errLinkClosed
	close(l.closed)
	go l.closeReader()
	return
}

// Shutdown instructs the Link to request that the remote peers shut down
// communication, while leaving the link in a state which can continue sending
// any queued data.
func (l *Link) Shutdown() (err error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	err = l.err
	l.err = errLinkShutdown
	close(l.shutdown)
	go l.closeReader()
	return
}

// Finish informs the peers connected to the Link that the Link will no longer
// be sending data. The link is still able to receive data.
func (l *Link) Finish() (err error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	err = l.err
	l.err = errLinkFinished
	close(l.sendPayload)
	go l.closeReader()
	return
}

// HandleConnection passes control over a websocket connection to the Link,
// returning when the connection closes.
func (l *Link) HandleConnection(c *websocket.Conn) error {
	l.mutex.Lock()
	if l.err != nil {
		writeAlert(c, l.err)
		c.Close()
		l.mutex.Unlock()
		return l.err
	}
	l.mutex.Unlock()
	return l.runConnection(c)
}
