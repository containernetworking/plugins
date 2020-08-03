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
	"encoding/binary"
	"fmt"
	"math"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// ChainHook specifies at which step in packet processing the Chain should be
// executed. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_hooks
type ChainHook uint32

// Possible ChainHook values.
const (
	ChainHookPrerouting  ChainHook = unix.NF_INET_PRE_ROUTING
	ChainHookInput       ChainHook = unix.NF_INET_LOCAL_IN
	ChainHookForward     ChainHook = unix.NF_INET_FORWARD
	ChainHookOutput      ChainHook = unix.NF_INET_LOCAL_OUT
	ChainHookPostrouting ChainHook = unix.NF_INET_POST_ROUTING
	ChainHookIngress     ChainHook = unix.NF_NETDEV_INGRESS
)

// ChainPriority orders the chain relative to Netfilter internal operations. See
// also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_priority
type ChainPriority int32

// Possible ChainPriority values.
const ( // from /usr/include/linux/netfilter_ipv4.h
	ChainPriorityFirst            ChainPriority = math.MinInt32
	ChainPriorityConntrackDefrag  ChainPriority = -400
	ChainPriorityRaw              ChainPriority = -300
	ChainPrioritySELinuxFirst     ChainPriority = -225
	ChainPriorityConntrack        ChainPriority = -200
	ChainPriorityMangle           ChainPriority = -150
	ChainPriorityNATDest          ChainPriority = -100
	ChainPriorityFilter           ChainPriority = 0
	ChainPrioritySecurity         ChainPriority = 50
	ChainPriorityNATSource        ChainPriority = 100
	ChainPrioritySELinuxLast      ChainPriority = 225
	ChainPriorityConntrackHelper  ChainPriority = 300
	ChainPriorityConntrackConfirm ChainPriority = math.MaxInt32
	ChainPriorityLast             ChainPriority = math.MaxInt32
)

// ChainType defines what this chain will be used for. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_types
type ChainType string

// Possible ChainType values.
const (
	ChainTypeFilter ChainType = "filter"
	ChainTypeRoute  ChainType = "route"
	ChainTypeNAT    ChainType = "nat"
)

// ChainPolicy defines what this chain default policy will be.
type ChainPolicy uint32

// Possible ChainPolicy values.
const (
	ChainPolicyDrop ChainPolicy = iota
	ChainPolicyAccept
)

// A Chain contains Rules. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains
type Chain struct {
	Name     string
	Table    *Table
	Hooknum  ChainHook
	Priority ChainPriority
	Type     ChainType
	Policy   *ChainPolicy
}

// AddChain adds the specified Chain. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Adding_base_chains
func (cc *Conn) AddChain(c *Chain) *Chain {
	cc.Lock()
	defer cc.Unlock()
	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(c.Table.Name + "\x00")},
		{Type: unix.NFTA_CHAIN_NAME, Data: []byte(c.Name + "\x00")},
	})

	if c.Type != "" {
		hookAttr := []netlink.Attribute{
			{Type: unix.NFTA_HOOK_HOOKNUM, Data: binaryutil.BigEndian.PutUint32(uint32(c.Hooknum))},
			{Type: unix.NFTA_HOOK_PRIORITY, Data: binaryutil.BigEndian.PutUint32(uint32(c.Priority))},
		}
		data = append(data, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NLA_F_NESTED | unix.NFTA_CHAIN_HOOK, Data: cc.marshalAttr(hookAttr)},
		})...)
	}

	if c.Policy != nil {
		data = append(data, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_CHAIN_POLICY, Data: binaryutil.BigEndian.PutUint32(uint32(*c.Policy))},
		})...)
	}
	if c.Type != "" {
		data = append(data, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_CHAIN_TYPE, Data: []byte(c.Type + "\x00")},
		})...)
	}
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWCHAIN),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: append(extraHeader(uint8(c.Table.Family), 0), data...),
	})

	return c
}

// DelChain deletes the specified Chain. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Deleting_chains
func (cc *Conn) DelChain(c *Chain) {
	cc.Lock()
	defer cc.Unlock()
	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(c.Table.Name + "\x00")},
		{Type: unix.NFTA_CHAIN_NAME, Data: []byte(c.Name + "\x00")},
	})

	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELCHAIN),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(extraHeader(uint8(c.Table.Family), 0), data...),
	})
}

// FlushChain removes all rules within the specified Chain. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Flushing_chain
func (cc *Conn) FlushChain(c *Chain) {
	cc.Lock()
	defer cc.Unlock()
	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(c.Table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(c.Name + "\x00")},
	})
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELRULE),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(extraHeader(uint8(c.Table.Family), 0), data...),
	})
}

// ListChains returns currently configured chains in the kernel
func (cc *Conn) ListChains() ([]*Chain, error) {
	conn, err := cc.dialNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETCHAIN),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: extraHeader(uint8(unix.AF_UNSPEC), 0),
	}

	response, err := conn.Execute(msg)
	if err != nil {
		return nil, err
	}

	var chains []*Chain
	for _, m := range response {
		c, err := chainFromMsg(m)
		if err != nil {
			return nil, err
		}

		chains = append(chains, c)
	}

	return chains, nil
}

func chainFromMsg(msg netlink.Message) (*Chain, error) {
	chainHeaderType := netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWCHAIN)
	if got, want := msg.Header.Type, chainHeaderType; got != want {
		return nil, fmt.Errorf("unexpected header type: got %v, want %v", got, want)
	}

	var c Chain

	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_CHAIN_NAME:
			c.Name = ad.String()
		case unix.NFTA_TABLE_NAME:
			c.Table = &Table{Name: ad.String()}
			// msg[0] carries TableFamily byte indicating whether it is IPv4, IPv6 or something else
			c.Table.Family = TableFamily(msg.Data[0])
		case unix.NFTA_CHAIN_TYPE:
			c.Type = ChainType(ad.String())
		case unix.NFTA_CHAIN_POLICY:
			policy := ChainPolicy(ad.Uint32())
			c.Policy = &policy
		case unix.NFTA_CHAIN_HOOK:
			ad.Do(func(b []byte) error {
				c.Hooknum, c.Priority, err = hookFromMsg(b)
				return err
			})
		}
	}

	return &c, nil
}

func hookFromMsg(b []byte) (ChainHook, ChainPriority, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return 0, 0, err
	}

	ad.ByteOrder = binary.BigEndian

	var hooknum ChainHook
	var prio ChainPriority

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_HOOK_HOOKNUM:
			hooknum = ChainHook(ad.Uint32())
		case unix.NFTA_HOOK_PRIORITY:
			prio = ChainPriority(ad.Uint32())
		}
	}

	return hooknum, prio, nil
}
