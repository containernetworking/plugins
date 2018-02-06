// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"

	"github.com/containernetworking/plugins/pkg/firewalld"

	"github.com/godbus/dbus"
)

// Only used for testcases to override the D-Bus connection
var testConn *dbus.Conn

type fwdBackend struct {
	conn *dbus.Conn
}

// fwdBackend implements the FirewallBackend interface
var _ FirewallBackend = &fwdBackend{}

func getConn() (*dbus.Conn, error) {
	if testConn != nil {
		return testConn, nil
	}
	return dbus.SystemBus()
}

func isFirewalldRunning() bool {
	conn, err := getConn()
	if err != nil {
		return false
	}
	return firewalld.IsRunning(conn)
}

func newFirewalldBackend(conf *FirewallNetConf) (FirewallBackend, error) {
	conn, err := getConn()
	if err != nil {
		return nil, err
	}

	backend := &fwdBackend{
		conn: conn,
	}
	return backend, nil
}

func (fb *fwdBackend) Add(conf *FirewallNetConf) error {
	for _, ip := range conf.PrevResult.IPs {
		if err := firewalld.AddSourceToZone(fb.conn, ip.Address.IP, conf.FirewalldZone); err != nil {
			return fmt.Errorf("failed to add the address %v to %v zone: %v", ip.Address.IP, conf.FirewalldZone, err)
		}
	}
	return nil
}

func (fb *fwdBackend) Del(conf *FirewallNetConf) error {
	for _, ip := range conf.PrevResult.IPs {
		firewalld.RemoveSourceFromZone(fb.conn, ip.Address.IP, conf.FirewalldZone)
	}
	return nil
}
