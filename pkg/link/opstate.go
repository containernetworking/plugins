// Copyright 2024 CNI authors
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

package link

import (
	"fmt"
	"time"

	"github.com/vishvananda/netlink"
)

func WaitForOperStateUp(linkName string) (netlink.Link, error) {
	var link netlink.Link
	var err error
	retries := []int{0, 50, 500, 1000, 1000}
	for idx, sleep := range retries {
		time.Sleep(time.Duration(sleep) * time.Millisecond)

		link, err = netlink.LinkByName(linkName)
		if err != nil {
			return nil, err
		}
		linkOpState := link.Attrs().OperState
		if linkOpState == netlink.OperUp {
			break
		}

		if idx == len(retries)-1 {
			return nil, fmt.Errorf("timeout waiting for %q state %q to be up", linkName, linkOpState)
		}
	}
	return link, nil
}

func SetUp(linkName string) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to retrieve link: %w", err)
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set %q up: %w", linkName, err)
	}
	return nil
}
