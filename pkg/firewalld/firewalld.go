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

package firewalld

import (
	"log"
	"net"
	"strings"

	"github.com/godbus/dbus"
)

const (
	dbusName               = "org.freedesktop.DBus"
	dbusPath               = "/org/freedesktop/DBus"
	dbusGetNameOwnerMethod = ".GetNameOwner"

	FirewalldName            = "org.fedoraproject.FirewallD1"
	FirewalldPath            = "/org/fedoraproject/FirewallD1"
	FirewalldZoneInterface   = "org.fedoraproject.FirewallD1.zone"
	FirewalldAddSourceMethod = ".addSource"
	FirewalldRemoveSourceMethod = ".removeSource"

	ErrZoneAlreadySet = "ZONE_ALREADY_SET"
)

// IsRunning checks whether firewalld is running.
func IsRunning(conn *dbus.Conn) bool {
	dbusObj := conn.Object(dbusName, dbusPath)
	var res string
	if err := dbusObj.Call(dbusName+dbusGetNameOwnerMethod, 0, FirewalldName).Store(&res); err != nil {
		return false
	}

	return true
}

// AddSourceToZone adds a firewalld rule which assigns the given source IP
// to the given zone.
func AddSourceToZone(conn *dbus.Conn, source net.IP, zone string) error {
	firewalldObj := conn.Object(FirewalldName, FirewalldPath)
	var res string
	if err := firewalldObj.Call(FirewalldZoneInterface+FirewalldAddSourceMethod, 0, zone, source.String()).Store(&res); err != nil {
		if strings.Contains(err.Error(), ErrZoneAlreadySet) {
			log.Printf("ip %v already bound to %q zone, it can mean that this address was assigned before to the another container without cleanup\n", source, zone)
		} else {
			return err
		}
	}

	return nil
}

// RemoveSourceFromZone removes firewalld rules which assigned the given source IP
// to the given zone.
func RemoveSourceFromZone(conn *dbus.Conn, source net.IP, zone string) error {
	firewalldObj := conn.Object(FirewalldName, FirewalldPath)
	var res string
	return firewalldObj.Call(FirewalldZoneInterface+FirewalldRemoveSourceMethod, 0, zone, source.String()).Store(&res)
}
