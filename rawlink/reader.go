/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package rawlink

import (
	"fmt"
	"time"

	"golang.org/x/net/websocket"
	"github.com/farsightsec/sielink"
)

type recoverError struct{ rerr interface{} }

func (r recoverError) Error() string {
	return fmt.Sprintf("panic: %v", r.rerr)
}

// runReader is the main connection receiver loop.
//
// It returns when it enocunters a read error (which it returns), receives a
// fatal Alert from its peer (which it returns), or receives a Finished message
// from its peer, in which case it returns nil.
//
func (l *Link) runReader(c *websocket.Conn, rshut chan<- struct{}) (err error) {
	defer func() {
		// The l.ControlFunc call needs to be in this closure for
		// changes to l.ControlFunc to take effect. Otherwise, only
		// the value at the time runReader is started will be used.
		l.TopologyFunc(c, nil)
		if r := recover(); r != nil {
			err = recoverError{r}
		}
	}()
	defer l.readWg.Done()

	m := new(sielink.Message)
	for {
		if err = readMessage(c, m); err != nil {
			return err
		}

		if hb := m.GetHeartbeat(); hb > 0 {
			hbDeadline := time.Duration(hb+hb/2) * time.Millisecond
			c.SetReadDeadline(time.Now().Add(hbDeadline))
		}

		switch m.GetMessageType() {
		case sielink.MessageType_DataMessage:
			l.recvPayload <- m.Payload
		case sielink.MessageType_TopologyMessage:
			l.TopologyFunc(c, m.GetTopology())
		case sielink.MessageType_AlertMessage:
			alert := m.GetAlert()
			if alert == nil {
				continue
			}
			if alert.GetLevel() == sielink.AlertLevel_FatalError {
				return alert
			}
			l.AlertFunc(c, alert)
		case sielink.MessageType_Finished:
			return nil
		case sielink.MessageType_Shutdown:
			rshut <- struct{}{}
		}

	}
}
