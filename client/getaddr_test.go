/*
 * Copyright (c) 2017 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package client

import (
	"net"
	"strings"
	"testing"
)

func TestHostPort(t *testing.T) {
	addrs, cn, err := getAddrs("www.google.com:80", "http", 80)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) > 1 {
		t.Error("host:port returned server list")
	}
	if !strings.HasSuffix(addrs[0], ":80") {
		t.Error("host:port returned non-matching port")
	}
	if cn != "www.google.com" {
		t.Error("incorrect server name: ", cn)
	}
}

func TestSRV(t *testing.T) {
	// Mock the SRV lookup so this test can run inside offline builds.
	orig := lookupSRV
	t.Cleanup(func() { lookupSRV = orig })
	lookupSRV = func(service, proto, name string) (string, []*net.SRV, error) {
		return "", []*net.SRV{
			{Target: "a.sie-network.net.", Port: 2022},
			{Target: "b.sie-network.net.", Port: 2022},
		}, nil
	}

	addrs, cn, err := getAddrs("submit.sie-network.net", "rsync", 22)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) <= 1 {
		t.Error("SIE SRV query returned fewer than expected targets")
	}
	if strings.HasSuffix(addrs[0], ":22") {
		t.Error("SIE SRV query returned default port")
	}
	if cn != "submit.sie-network.net" {
		t.Error("incorrect server name: ", cn)
	}
}

func TestSRVNonexistent(t *testing.T) {
	// Mock a missing SRV record so this test can run inside offline builds.
	orig := lookupSRV
	t.Cleanup(func() { lookupSRV = orig })
	lookupSRV = func(service, proto, name string) (string, []*net.SRV, error) {
		return "", nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}

	addrs, cn, err := getAddrs("www.google.com", "https", 443)
	if err != nil {
		t.Error(err)
	}
	if len(addrs) != 1 {
		t.Error("Nonexistent SRV returned multiple addresses")
	}
	if !strings.HasSuffix(addrs[0], ":443") {
		t.Error("Nonexistent SRV returned non-default port")
	}
	if cn != "www.google.com" {
		t.Error("incorrect server name: ", cn)
	}
}
