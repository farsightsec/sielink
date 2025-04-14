/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package rawlink

import (
	"google.golang.org/protobuf/proto"
	"github.com/farsightsec/sielink"
)

func (l *Link) setHeartbeat(hbtime uint32) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.configMessage = newConfigMessage(
		l.configMessage.Topology.Subscription,
		l.configMessage.Topology.Path,
		proto.Uint32(hbtime),
	)
}

func (l *Link) linkConfigMessage() (m *sielink.Message, ch <-chan struct{}) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.configMessage, l.configUpdate
}

func newConfigMessage(subs []*sielink.Subscription, paths []*sielink.Path, hb *uint32) *sielink.Message {
	return &sielink.Message{
		ProtocolVersion: sielink.SupportedVersions,
		MessageType:     sielink.MessageType_TopologyMessage.Enum(),
		Heartbeat:       hb,
		Topology: &sielink.Topology{
			Subscription: subs,
			Path:         paths,
		},
	}
}
