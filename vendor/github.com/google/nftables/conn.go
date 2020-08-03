// Copyright 2018 Google LLC. All Rights Reserved.
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

package nftables

import (
	"fmt"
	"sync"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// A Conn represents a netlink connection of the nftables family.
//
// All methods return their input, so that variables can be defined from string
// literals when desired.
//
// Commands are buffered. Flush sends all buffered commands in a single batch.
type Conn struct {
	TestDial nltest.Func // for testing only; passed to nltest.Dial
	NetNS    int         // Network namespace netlink will interact with.
	sync.Mutex
	messages []netlink.Message
	err      error
}

// Flush sends all buffered commands in a single batch to nftables.
func (cc *Conn) Flush() error {
	cc.Lock()
	defer func() {
		cc.messages = nil
		cc.Unlock()
	}()
	if len(cc.messages) == 0 {
		// Messages were already programmed, returning nil
		return nil
	}
	if cc.err != nil {
		return cc.err // serialization error
	}
	conn, err := cc.dialNetlink()
	if err != nil {
		return err
	}

	defer conn.Close()

	if _, err := conn.SendMessages(batch(cc.messages)); err != nil {
		return fmt.Errorf("SendMessages: %w", err)
	}

	if _, err := conn.Receive(); err != nil {
		return fmt.Errorf("Receive: %w", err)
	}

	return nil
}

// FlushRuleset flushes the entire ruleset. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Operations_at_ruleset_level
func (cc *Conn) FlushRuleset() {
	cc.Lock()
	defer cc.Unlock()
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELTABLE),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: extraHeader(0, 0),
	})
}

func (cc *Conn) dialNetlink() (*netlink.Conn, error) {
	if cc.TestDial != nil {
		return nltest.Dial(cc.TestDial), nil
	}

	disableNSLockThread := false
	if cc.NetNS == 0 {
		// Since process is operating in main namespace, there is no reason to have NSLockThread lock,
		// as it causes some performance penalties.
		disableNSLockThread = true
	}
	return netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: cc.NetNS, DisableNSLockThread: disableNSLockThread})
}

func (cc *Conn) setErr(err error) {
	if cc.err != nil {
		return
	}
	cc.err = err
}

func (cc *Conn) marshalAttr(attrs []netlink.Attribute) []byte {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		cc.setErr(err)
		return nil
	}
	return b
}

func (cc *Conn) marshalExpr(e expr.Any) []byte {
	b, err := expr.Marshal(e)
	if err != nil {
		cc.setErr(err)
		return nil
	}
	return b
}

func batch(messages []netlink.Message) []netlink.Message {
	batch := []netlink.Message{
		{
			Header: netlink.Header{
				Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_BEGIN),
				Flags: netlink.Request,
			},
			Data: extraHeader(0, unix.NFNL_SUBSYS_NFTABLES),
		},
	}

	batch = append(batch, messages...)

	batch = append(batch, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_END),
			Flags: netlink.Request,
		},
		Data: extraHeader(0, unix.NFNL_SUBSYS_NFTABLES),
	})

	return batch
}
