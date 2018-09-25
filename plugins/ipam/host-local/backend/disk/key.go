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

package disk

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
)

type kindValue struct {
	Kind  string          `json:"kind"`
	Value json.RawMessage `json:"value"`
}

type KeyKind string

const KindReservationV0 = "host-local-v0"
const KindReservationV1 = "host-local-v1"

type ReservationV1JSON struct {
	Kind  KeyKind       `json:"kind"`
	Value ReservationV1 `json:"value"`
}

type ReservationV1 struct {
	ID string `json:"id"`
	IF string `json:"if"`
}

func (r *ReservationV1) Key() *backend.Key {
	return &backend.Key{
		ID: r.ID,
		IF: r.IF,
	}
}

// KeyFromFile parses an ip serialization record from a file
func ReadKey(b []byte) (*backend.Key, KeyKind, error) {
	kv := kindValue{}

	err := json.Unmarshal(b, &kv)
	// If it fails to unmarshal, assume it's the pre-json kind, where we just
	// wrote the containerid to the file directly
	if err != nil {
		id := strings.TrimSpace(string(b))
		return &backend.Key{ID: id}, KindReservationV0, nil
	}

	switch kv.Kind {
	case "":
		// sort of awkward, but probably just a weird container id
		id := strings.TrimSpace(string(b))
		return &backend.Key{ID: id}, KindReservationV0, nil
	case KindReservationV1:
		r := ReservationV1{}
		err := json.Unmarshal(kv.Value, &r)
		if err != nil {
			return nil, "", fmt.Errorf("failed to unmarshal: %v", err)
		}
		return r.Key(), KindReservationV1, nil
	}

	return nil, "", fmt.Errorf("unknown key kind %s", kv.Kind)
}

// WriteKey shals a key to bytes
func WriteKey(k *backend.Key) []byte {
	r := ReservationV1JSON{
		Kind: KindReservationV1,
		Value: ReservationV1{
			ID: k.ID,
			IF: k.IF,
		},
	}
	b, _ := json.Marshal(r)
	return b
}

// Matches returns true if bytes (on disk) match a given key
//
// Previous editions of the CNI spec specified a primary key of (network, container id), but
// cni v0.7.0 requires it to be (network, container id, ifname).  This changed
// the store format from plain text to json. However, we want to be able to
// clean up stores from old versions, so we will match if the if name is the same, or
// if the ifname on disk is empty and we know it was stored in the old format
func Matches(k *backend.Key, b []byte) (bool, error) {
	k1, kind, err := ReadKey(b)
	if err != nil {
		return false, err
	}

	switch kind {
	case KindReservationV0:
		return k.ID == k1.ID, nil
	case KindReservationV1:
		return k.Equals(k1), nil
	}
	return false, fmt.Errorf("unreachable")
}
