/*
 * This file is part of the go-nft project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2021 Red Hat, Inc.
 *
 */

package schema

import (
	"encoding/json"
	"fmt"
)

type Rule struct {
	Family  string      `json:"family"`
	Table   string      `json:"table"`
	Chain   string      `json:"chain"`
	Expr    []Statement `json:"expr,omitempty"`
	Handle  *int        `json:"handle,omitempty"`
	Index   *int        `json:"index,omitempty"`
	Comment string      `json:"comment,omitempty"`
}

type Statement struct {
	Match *Match `json:"match,omitempty"`
	Verdict
}

type Verdict struct {
	SimpleVerdict
	Jump *ToTarget `json:"jump,omitempty"`
	Goto *ToTarget `json:"goto,omitempty"`
}

type SimpleVerdict struct {
	Accept   bool `json:"-"`
	Continue bool `json:"-"`
	Drop     bool `json:"-"`
	Return   bool `json:"-"`
}

type ToTarget struct {
	Target string `json:"target"`
}

type Match struct {
	Op    string     `json:"op"`
	Left  Expression `json:"left"`
	Right Expression `json:"right"`
}

type Expression struct {
	String  *string  `json:"-"`
	Bool    *bool    `json:"-"`
	Float64 *float64 `json:"-"`
	Payload *Payload `json:"payload,omitempty"`
	// RowData accepts arbitrary data which cannot be composed from the existing schema.
	// Use `json.RawMessage()` or `[]byte()` for the value.
	// Example:
	// `schema.Expression{RowData: json.RawMessage(`{"meta":{"key":"iifname"}}`)}`
	RowData json.RawMessage `json:"-"`
}

type Payload struct {
	Protocol string `json:"protocol"`
	Field    string `json:"field"`
}

// Verdict Operations
const (
	VerdictAccept   = "accept"
	VerdictContinue = "continue"
	VerdictDrop     = "drop"
	VerdictReturn   = "return"
)

// Match Operators
const (
	OperAND = "&"  // Binary AND
	OperOR  = "|"  // Binary OR
	OperXOR = "^"  // Binary XOR
	OperLSH = "<<" // Left shift
	OperRSH = ">>" // Right shift
	OperEQ  = "==" // Equal
	OperNEQ = "!=" // Not equal
	OperLS  = "<"  // Less than
	OperGR  = ">"  // Greater than
	OperLSE = "<=" // Less than or equal to
	OperGRE = ">=" // Greater than or equal to
	OperIN  = "in" // Perform a lookup, i.e. test if bits on RHS are contained in LHS value
)

// Payload Expressions
const (
	PayloadKey = "payload"
	// Ethernet
	PayloadProtocolEther   = "ether"
	PayloadFieldEtherDAddr = "daddr"
	PayloadFieldEtherSAddr = "saddr"
	PayloadFieldEtherType  = "type"

	// IP (common)
	PayloadFieldIPVer   = "version"
	PayloadFieldIPDscp  = "dscp"
	PayloadFieldIPEcn   = "ecn"
	PayloadFieldIPLen   = "length"
	PayloadFieldIPSAddr = "saddr"
	PayloadFieldIPDAddr = "daddr"

	// IPv4
	PayloadProtocolIP4      = "ip"
	PayloadFieldIP4HdrLen   = "hdrlength"
	PayloadFieldIP4Id       = "id"
	PayloadFieldIP4FragOff  = "frag-off"
	PayloadFieldIP4Ttl      = "ttl"
	PayloadFieldIP4Protocol = "protocol"
	PayloadFieldIP4Chksum   = "checksum"

	// IPv6
	PayloadProtocolIP6       = "ip6"
	PayloadFieldIP6FlowLabel = "flowlabel"
	PayloadFieldIP6NextHdr   = "nexthdr"
	PayloadFieldIP6HopLimit  = "hoplimit"
)

func (s Statement) MarshalJSON() ([]byte, error) {
	type _Statement Statement
	statement := _Statement(s)

	// Convert to a dynamic structure
	data, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}
	dynamicStructure := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &dynamicStructure); err != nil {
		return nil, err
	}

	switch {
	case s.Accept:
		dynamicStructure[VerdictAccept] = nil
	case s.Continue:
		dynamicStructure[VerdictContinue] = nil
	case s.Drop:
		dynamicStructure[VerdictDrop] = nil
	case s.Return:
		dynamicStructure[VerdictReturn] = nil
	}

	data, err = json.Marshal(dynamicStructure)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *Statement) UnmarshalJSON(data []byte) error {
	type _Statement Statement
	statement := _Statement{}

	if err := json.Unmarshal(data, &statement); err != nil {
		return err
	}
	*s = Statement(statement)

	dynamicStructure := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &dynamicStructure); err != nil {
		return err
	}
	_, s.Accept = dynamicStructure[VerdictAccept]
	_, s.Continue = dynamicStructure[VerdictContinue]
	_, s.Drop = dynamicStructure[VerdictDrop]
	_, s.Return = dynamicStructure[VerdictReturn]

	return nil
}

func (e Expression) MarshalJSON() ([]byte, error) {
	var dynamicStruct interface{}

	switch {
	case e.RowData != nil:
		return e.RowData, nil
	case e.String != nil:
		dynamicStruct = *e.String
	case e.Float64 != nil:
		dynamicStruct = *e.Float64
	case e.Bool != nil:
		dynamicStruct = *e.Bool
	default:
		type _Expression Expression
		dynamicStruct = _Expression(e)
	}

	return json.Marshal(dynamicStruct)
}

func (e *Expression) UnmarshalJSON(data []byte) error {
	var dynamicStruct interface{}
	if err := json.Unmarshal(data, &dynamicStruct); err != nil {
		return err
	}

	switch dynamicStruct.(type) {
	case string:
		d := dynamicStruct.(string)
		e.String = &d
	case float64:
		d := dynamicStruct.(float64)
		e.Float64 = &d
	case bool:
		d := dynamicStruct.(bool)
		e.Bool = &d
	case map[string]interface{}:
		type _Expression Expression
		expression := _Expression(*e)
		if err := json.Unmarshal(data, &expression); err != nil {
			return err
		}
		*e = Expression(expression)
	default:
		return fmt.Errorf("unsupported field type in expression: %T(%v)", dynamicStruct, dynamicStruct)
	}

	if e.String == nil && e.Float64 == nil && e.Bool == nil && e.Payload == nil {
		e.RowData = data
	}

	return nil
}

func Accept() Verdict {
	return Verdict{SimpleVerdict: SimpleVerdict{Accept: true}}
}

func Continue() Verdict {
	return Verdict{SimpleVerdict: SimpleVerdict{Continue: true}}
}

func Drop() Verdict {
	return Verdict{SimpleVerdict: SimpleVerdict{Drop: true}}
}

func Return() Verdict {
	return Verdict{SimpleVerdict: SimpleVerdict{Return: true}}
}
