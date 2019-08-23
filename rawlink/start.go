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

func (l *Link) runConnection(c *websocket.Conn) (err error) {
	defer c.Close()

	localConfig, configUpdate := l.linkConfigMessage()

	if err = writeMessage(c, localConfig); err != nil {
		return
	}

	remoteConfig := new(sielink.Message)

	// read remote config message
	if err = readMessage(c, remoteConfig); err != nil {
		return
	}

	// check version, etc. from config message
	remoteVersion, err := l.processConfig(c, remoteConfig)
	if err != nil {
		return err
	}

	// Placeholder for future protocol fall-back.
	switch remoteVersion {
	case 1:
	default:
	}

	go l.sendConfigMessage(c, configUpdate)
	go sendHeartbeat(c, l.Heartbeat)

	receiveShutdown := make(chan struct{}, 1)
	receiveError := make(chan error, 1)

	l.readWg.Add(1)
	go func() {
		receiveError <- l.runReader(c, receiveShutdown)
	}()

	return l.runSender(c, receiveError, receiveShutdown)
}

func matchVersion(v []uint32) (max uint32) {
	for i := range v {
		for _, sv := range sielink.SupportedVersions {
			if v[i] == sv && sv > max {
				max = sv
			}
		}
	}
	return
}

func (l *Link) processConfig(c *websocket.Conn, m *sielink.Message) (uint32, error) {
	mv := m.GetProtocolVersion()
	v := matchVersion(mv)
	if v == 0 {
		err := fmt.Errorf("Versions %v not supported", mv)
		writeAlert(c, err)
		return 0, err
	}

	if m.GetHeartbeat() > 0 {
		d := time.Millisecond * time.Duration(m.GetHeartbeat())
		c.SetReadDeadline(time.Now().Add(d))
	}

	switch m.GetMessageType() {
	case sielink.MessageType_Heartbeat:
	case sielink.MessageType_TopologyMessage:
		l.TopologyFunc(c, m.GetTopology())
	case sielink.MessageType_AlertMessage:
		alert := m.GetAlert()
		if alert.GetLevel() == sielink.AlertLevel_FatalError {
			return 0, alert
		}
		l.AlertFunc(c, alert)
	default:
		err := fmt.Errorf("Unexpected message type %s", m.GetMessageType())
		writeAlert(c, err)
		return v, err
	}
	return v, nil
}
