/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package sielink

import (
	"fmt"
	"google.golang.org/protobuf/proto"
)

// ProtocolVersion is the version of the protocol implemented
// in this version of the package.
var ProtocolVersion uint32 = 1

const (
	SieMessageType = 1
)

// SupportedVersions lists the protocol versions this version of
// the package can interoperate with.
var SupportedVersions = []uint32{ProtocolVersion}

//go:generate protoc --go_out=. sielink.proto

// A Link is the basic interface to a collection of sielink connections.
type Link interface {
	// Send sends a payload on the Link, blocking if there is no available
	// connection, returning an error if the Link is closing.
	Send(*Payload) error
	// Receive returns a channel from which the caller can read the next
	// payload received on any connection. If all connections have announced
	// their intention to cease sending, this channel is closed.
	Receive() <-chan *Payload
	// Close closes all connections involved in the Link
	Close() error
}

// The Error() method allows an Alert to be returned and handled as an error.
func (a *Alert) Error() string {
	return fmt.Sprintf("Remote host reported %s: %s",
		a.GetLevel().String(), a.GetMessage())
}

// RecordLinkLoss resets the LinkLoss counters after adding their values
// to the PathLoss counters.
func (p *Payload) RecordLinkLoss() {
	pl := p.GetPathLoss()
	if pl == nil {
		return
	}
	ll := p.GetLinkLoss()
	if ll == nil {
		p.LinkLoss = pl
		p.PathLoss = nil
		return
	}
	*p.PathLoss.Bytes += ll.GetBytes()
	*p.PathLoss.Payloads += ll.GetPayloads()
	p.LinkLoss.Reset()
}

// RecordDiscard updates the link Loss counters to record the
// discarding of the supplied payload.
func (p *Payload) RecordDiscard(disc *Payload) {
	if p.LinkLoss == nil {
		p.LinkLoss = &LossCounter{
			Bytes:    proto.Uint64(uint64(len(disc.Data))),
			Payloads: proto.Uint64(1),
		}
		return
	}
	*p.LinkLoss.Bytes += uint64(len(disc.Data))
	*p.LinkLoss.Payloads++
}

// GetDestination returns the destination site of the Path.
func (p *Path) GetDestination() uint32 {
	if p.Site != nil {
		return p.Site[0]
	}
	return 0
}

// GetNexthop returns the Next site on the path.
func (p *Path) GetNexthop() uint32 {
	if p.Site != nil {
		return p.Site[len(p.Site)-1]
	}
	return 0
}
