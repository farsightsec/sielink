/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package rawlink

import (
	"time"

	"github.com/farsightsec/sielink"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

func sendHeartbeat(c *websocket.Conn, d time.Duration) {
	if d == 0 {
		return
	}
	ms := uint32(d / time.Millisecond)
	heartbeatMessage := &sielink.Message{
		ProtocolVersion: sielink.SupportedVersions,
		MessageType:     sielink.MessageType_Heartbeat.Enum(),
		Heartbeat:       proto.Uint32(ms),
	}
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		c.SetWriteDeadline(time.Now().Add(d + d/2))
		if err := writeMessage(c, heartbeatMessage); err != nil {
			return
		}
		<-t.C
	}
}

func (l *Link) sendConfigMessage(c *websocket.Conn, upd <-chan struct{}) {
	var m *sielink.Message
	for {
		<-upd
		m, upd = l.linkConfigMessage()
		if err := writeMessage(c, m); err != nil {
			return
		}
	}
}

// runSender is the main sender loop for the connection. It runs
// in parallel with sendConfigMessage and sendHeartbeat.
func (l *Link) runSender(c *websocket.Conn, receiveError <-chan error,
	receiveShutdown <-chan struct{}) (err error) {

	for {
		select {
		case p, ok := <-l.sendPayload:
			if !ok {
				return finishConnection(c, receiveError)
			}
			if err = writePayload(c, p); err != nil {
				return err
			}
		case <-l.closed:
			return
		case <-l.shutdown:
			return l.shutdownConnection(c, receiveError)
		case <-receiveShutdown:
			return finishConnection(c, receiveError)
		case err = <-receiveError:
			if err != nil {
				return
			}
			// A nil receiveError return implies the remote has sent a
			// Finished message. We do not expect future values on this
			// channel, so we set it to nil as an indicator that the
			// remote end has sent Finished.
			receiveError = nil
		}
	}
}

// shutDownConnection runs the sender side of a connection which has
// requested a shutdown. It continues sending data until l.Finish() is
// called, or a receive error occurs.
func (l *Link) shutdownConnection(c *websocket.Conn, ech <-chan error) error {
	shutdownMessage := &sielink.Message{
		ProtocolVersion: sielink.SupportedVersions,
		MessageType:     sielink.MessageType_Shutdown.Enum(),
	}
	if err := writeMessage(c, shutdownMessage); err != nil {
		return err
	}
	for {
		select {
		case p, ok := <-l.sendPayload:
			if !ok {
				return finishConnection(c, ech)
			}
			if err := writePayload(c, p); err != nil {
				return err
			}
		case err := <-ech:
			if err != nil {
				return err
			}
			ech = nil
		}
	}
}

// finish Connection sends a Finished message, then waits for the
// receiver goroutine to finish. If it has already finished, ech
// will be nil, and finishConnection will return immediately after
// sending the Finished message.
func finishConnection(c *websocket.Conn, ech <-chan error) error {
	finishedMessage := &sielink.Message{
		ProtocolVersion: sielink.SupportedVersions,
		MessageType:     sielink.MessageType_Finished.Enum(),
	}

	if err := writeMessage(c, finishedMessage); err != nil {
		return err
	}
	if ech == nil {
		return nil
	}
	return <-ech
}
