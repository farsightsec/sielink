/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package rawlink

import (
	"github.com/farsightsec/sielink"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
)

func readMessage(c *websocket.Conn, m *sielink.Message) error {
	var b []byte
	_, b, err := c.ReadMessage()
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, m)
}

func writeMessage(c *websocket.Conn, m *sielink.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	return c.WriteMessage(1, b)
}

func writeAlert(c *websocket.Conn, err error) error {
	return writeMessage(c, &sielink.Message{
		ProtocolVersion: sielink.SupportedVersions,
		MessageType:     sielink.MessageType_AlertMessage.Enum(),
		Alert: &sielink.Alert{
			Level:   sielink.AlertLevel_FatalError.Enum(),
			Message: proto.String(err.Error()),
		},
	})
}

func writePayload(c *websocket.Conn, p *sielink.Payload) error {
	dataMessage := &sielink.Message{
		ProtocolVersion: sielink.SupportedVersions,
		MessageType:     sielink.MessageType_DataMessage.Enum(),
		Payload:         p,
	}
	return writeMessage(c, dataMessage)
}
