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

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var ruleHeaderType = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWRULE)

type ruleOperation uint32

// Possible PayloadOperationType values.
const (
	operationAdd ruleOperation = iota
	operationInsert
	operationReplace
)

// A Rule does something with a packet. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management
type Rule struct {
	Table    *Table
	Chain    *Chain
	Position uint64
	Handle   uint64
	Exprs    []expr.Any
	UserData []byte
}

// GetRule returns the rules in the specified table and chain.
func (cc *Conn) GetRule(t *Table, c *Chain) ([]*Rule, error) {
	conn, err := cc.dialNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(t.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(c.Name + "\x00")},
	})
	if err != nil {
		return nil, err
	}

	message := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETRULE),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Dump | unix.NLM_F_ECHO,
		},
		Data: append(extraHeader(uint8(t.Family), 0), data...),
	}

	if _, err := conn.SendMessages([]netlink.Message{message}); err != nil {
		return nil, fmt.Errorf("SendMessages: %v", err)
	}

	reply, err := conn.Receive()
	if err != nil {
		return nil, fmt.Errorf("Receive: %v", err)
	}
	var rules []*Rule
	for _, msg := range reply {
		r, err := ruleFromMsg(msg)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}

	return rules, nil
}

// AddRule adds the specified Rule
func (cc *Conn) newRule(r *Rule, op ruleOperation) *Rule {
	cc.Lock()
	defer cc.Unlock()
	exprAttrs := make([]netlink.Attribute, len(r.Exprs))
	for idx, expr := range r.Exprs {
		exprAttrs[idx] = netlink.Attribute{
			Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM,
			Data: cc.marshalExpr(expr),
		}
	}

	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(r.Table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(r.Chain.Name + "\x00")},
	})

	if r.Handle != 0 {
		data = append(data, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(r.Handle)},
		})...)
	}

	data = append(data, cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: cc.marshalAttr(exprAttrs)},
	})...)

	msgData := []byte{}

	msgData = append(msgData, data...)
	var flags netlink.HeaderFlags
	if r.UserData != nil {
		msgData = append(msgData, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_USERDATA, Data: r.UserData},
		})...)
	}

	switch op {
	case operationAdd:
		flags = netlink.Request | netlink.Acknowledge | netlink.Create | unix.NLM_F_ECHO | unix.NLM_F_APPEND
	case operationInsert:
		flags = netlink.Request | netlink.Acknowledge | netlink.Create | unix.NLM_F_ECHO
	case operationReplace:
		flags = netlink.Request | netlink.Acknowledge | netlink.Replace | unix.NLM_F_ECHO | unix.NLM_F_REPLACE
	}

	if r.Position != 0 {
		msgData = append(msgData, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_POSITION, Data: binaryutil.BigEndian.PutUint64(r.Position)},
		})...)
	}

	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  ruleHeaderType,
			Flags: flags,
		},
		Data: append(extraHeader(uint8(r.Table.Family), 0), msgData...),
	})

	return r
}

func (cc *Conn) ReplaceRule(r *Rule) *Rule {
	return cc.newRule(r, operationReplace)
}

func (cc *Conn) AddRule(r *Rule) *Rule {
	if r.Handle != 0 {
		return cc.newRule(r, operationReplace)
	}

	return cc.newRule(r, operationAdd)
}

func (cc *Conn) InsertRule(r *Rule) *Rule {
	if r.Handle != 0 {
		return cc.newRule(r, operationReplace)
	}

	return cc.newRule(r, operationInsert)
}

// DelRule deletes the specified Rule, rule's handle cannot be 0
func (cc *Conn) DelRule(r *Rule) error {
	cc.Lock()
	defer cc.Unlock()
	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(r.Table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(r.Chain.Name + "\x00")},
	})
	if r.Handle == 0 {
		return fmt.Errorf("rule's handle cannot be 0")
	}
	data = append(data, cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(r.Handle)},
	})...)
	flags := netlink.Request | netlink.Acknowledge

	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELRULE),
			Flags: flags,
		},
		Data: append(extraHeader(uint8(r.Table.Family), 0), data...),
	})

	return nil
}

func exprsFromMsg(b []byte) ([]expr.Any, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian
	var exprs []expr.Any
	for ad.Next() {
		ad.Do(func(b []byte) error {
			ad, err := netlink.NewAttributeDecoder(b)
			if err != nil {
				return err
			}
			ad.ByteOrder = binary.BigEndian
			var name string
			for ad.Next() {
				switch ad.Type() {
				case unix.NFTA_EXPR_NAME:
					name = ad.String()
				case unix.NFTA_EXPR_DATA:
					var e expr.Any
					switch name {
					case "meta":
						e = &expr.Meta{}
					case "cmp":
						e = &expr.Cmp{}
					case "counter":
						e = &expr.Counter{}
					case "payload":
						e = &expr.Payload{}
					case "lookup":
						e = &expr.Lookup{}
					case "immediate":
						e = &expr.Immediate{}
					case "bitwise":
						e = &expr.Bitwise{}
					case "redir":
						e = &expr.Redir{}
					case "nat":
						e = &expr.NAT{}
					case "limit":
						e = &expr.Limit{}
					case "dynset":
						e = &expr.Dynset{}
					}
					if e == nil {
						// TODO: introduce an opaque expression type so that users know
						// something is here.
						continue // unsupported expression type
					}

					ad.Do(func(b []byte) error {
						if err := expr.Unmarshal(b, e); err != nil {
							return err
						}
						// Verdict expressions are a special-case of immediate expressions, so
						// if the expression is an immediate writing nothing into the verdict
						// register (invalid), re-parse it as a verdict expression.
						if imm, isImmediate := e.(*expr.Immediate); isImmediate && imm.Register == unix.NFT_REG_VERDICT && len(imm.Data) == 0 {
							e = &expr.Verdict{}
							if err := expr.Unmarshal(b, e); err != nil {
								return err
							}
						}
						exprs = append(exprs, e)
						return nil
					})
				}
			}
			return ad.Err()
		})
	}
	return exprs, ad.Err()
}

func ruleFromMsg(msg netlink.Message) (*Rule, error) {
	if got, want := msg.Header.Type, ruleHeaderType; got != want {
		return nil, fmt.Errorf("unexpected header type: got %v, want %v", got, want)
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian
	var r Rule
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_TABLE:
			r.Table = &Table{Name: ad.String()}
		case unix.NFTA_RULE_CHAIN:
			r.Chain = &Chain{Name: ad.String()}
		case unix.NFTA_RULE_EXPRESSIONS:
			ad.Do(func(b []byte) error {
				r.Exprs, err = exprsFromMsg(b)
				return err
			})
		case unix.NFTA_RULE_POSITION:
			r.Position = ad.Uint64()
		case unix.NFTA_RULE_HANDLE:
			r.Handle = ad.Uint64()
		case unix.NFTA_RULE_USERDATA:
			r.UserData = ad.Bytes()
		}
	}
	return &r, ad.Err()
}
