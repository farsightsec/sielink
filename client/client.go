/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/farsightsec/sielink"
	"github.com/farsightsec/sielink/rawlink"
)

// A Client Link allows the caller to subscribe to a number of channels
// in addition to the base Link functionality.
type Client interface {
	sielink.Link

	// DialAndHandle initiates a connection to the provided URL and
	// runs the Link protocol over this connection. It returns an error,
	// if any, when the connection ends.
	DialAndHandle(uri string) error

	// DialAndHandleSRV initiates a connection to the provided URL and
	// runs the Link protocol over this connection. If the host name
	// of the URL does not have a specified port, and the hostname
	// has a SRV record for http / tcp, DialAndHandleSRV will connect
	// using the SRV record hosts and ports. Otherwise, DialAndHandleSRV
	// will behave exactly like DialAndHandle.
	//  DialAndHandleSRV(uri string) error

	// Subscribe requests data available on the supplied channels
	// from the servers.
	Subscribe(channels ...uint32)

	Ready() chan struct{}
}

// Config contains the configuration for a sieproto Client link.
type Config struct {
	Heartbeat time.Duration
	URL       string
	APIKey    string
	TLSConfig *tls.Config
}

type basicClient struct {
	*rawlink.Link
	Config
	ready chan struct{}
}

func (c *basicClient) Subscribe(channels ...uint32) {
	c.SetSubscription([]*sielink.Subscription{
		&sielink.Subscription{Channel: channels},
	})
}

func (c *basicClient) DialAndHandle(serverurl string) error {

	rh := http.Header{}
	if c.APIKey != "" {
		rh.Set("X-API-Key", c.APIKey)
	}

	dialer := websocket.Dialer{
		TLSClientConfig: c.TLSConfig,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	conn, _, err := dialer.Dial(serverurl, rh)

	if err != nil {
		return err
	}

	close(c.ready)
	return c.HandleConnection(conn)
}

func (c *basicClient) Ready() chan struct{} {
	return c.ready
}

// NewClient creates a Link appropriate for use as a client for uploading
// and subscribing to data from a collection of routers.
func NewClient(conf *Config) Client {
	rl := rawlink.NewLink()
	rl.Heartbeat = conf.Heartbeat
	return &basicClient{rl, *conf, make(chan struct{})}
}

func getAddrs(name, service string, port uint16) (addrs []string, cn string, err error) {
	host, sport, err := net.SplitHostPort(name)
	if err == nil {
		addrs = []string{fmt.Sprintf("%s:%s", host, sport)}
		cn = host
		return
	}

	cn = name
	_, srvs, err := net.LookupSRV(service, "tcp", name)
	if err == nil {
		for _, s := range srvs {
			addrs = append(addrs, fmt.Sprintf("%s:%d", s.Target, s.Port))
		}
		return
	}

	if t, ok := err.(*net.DNSError); ok && t.Temporary() {
		return
	}

	addrs = []string{fmt.Sprintf("%s:%d", name, port)}
	err = nil
	return
}
