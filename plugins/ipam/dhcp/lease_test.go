// Copyright 2015 CNI authors
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
	"reflect"
	"testing"

	"github.com/d2g/dhcp4"
)

func TestDHCPLease_clientIdOptions(t *testing.T) {
	type fields struct {
		clientID      string
		optsProviding map[dhcp4.OptionCode][]byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			"customized option override the client id",
			fields{
				clientID:      "hehe",
				optsProviding: map[dhcp4.OptionCode][]byte{dhcp4.OptionClientIdentifier: []byte("good")},
			},
			[]byte{0x00, 0x67, 0x6f, 0x6f, 0x64},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &DHCPLease{
				clientID:      tt.fields.clientID,
				optsProviding: tt.fields.optsProviding,
			}
			if got := l.getOptionsWithClientId(); !reflect.DeepEqual(got[dhcp4.OptionClientIdentifier], tt.want) {
				t.Errorf("DHCPLease.getOptionsWithClientId() = %v, want %v", got, tt.want)
			}
			if got := l.getAllOptions(); !reflect.DeepEqual(got[dhcp4.OptionClientIdentifier], tt.want) {
				t.Errorf("DHCPLease.getAllOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}
