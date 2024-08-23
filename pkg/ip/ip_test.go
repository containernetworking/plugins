// Copyright 2021 CNI authors
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

package ip

import (
	"encoding/json"
	"fmt"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("IP Operations", func() {
	It("Parse", func() {
		testCases := []struct {
			ipStr    string
			expected *IP
		}{
			{
				"192.168.0.10",
				newIP(net.IPv4(192, 168, 0, 10), nil),
			},
			{
				"2001:db8::1",
				newIP(net.ParseIP("2001:db8::1"), nil),
			},
			{
				"192.168.0.10/24",
				newIP(net.IPv4(192, 168, 0, 10), net.IPv4Mask(255, 255, 255, 0)),
			},
			{
				"2001:db8::1/64",
				newIP(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)),
			},
			{
				"invalid",
				nil,
			},
		}

		for _, test := range testCases {
			ip := ParseIP(test.ipStr)

			Expect(ip).To(Equal(test.expected))
		}
	})

	It("String", func() {
		testCases := []struct {
			ip       *IP
			expected string
		}{
			{
				newIP(net.IPv4(192, 168, 0, 1), net.IPv4Mask(255, 255, 255, 0)),
				"192.168.0.1/24",
			},
			{
				newIP(net.IPv4(192, 168, 0, 2), nil),
				"192.168.0.2",
			},
			{
				newIP(net.ParseIP("2001:db8::1"), nil),
				"2001:db8::1",
			},
			{
				newIP(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)),
				"2001:db8::1/64",
			},
			{
				newIP(nil, nil),
				"<nil>",
			},
		}

		for _, test := range testCases {
			Expect(test.ip.String()).To(Equal(test.expected))
		}
	})

	It("ToIP", func() {
		testCases := []struct {
			ip          *IP
			expectedLen int
			expectedIP  net.IP
		}{
			{
				newIP(net.IPv4(192, 168, 0, 1), net.IPv4Mask(255, 255, 255, 0)),
				net.IPv4len,
				net.IP{192, 168, 0, 1},
			},
			{
				newIP(net.IPv4(192, 168, 0, 2), nil),
				net.IPv4len,
				net.IP{192, 168, 0, 2},
			},
			{
				newIP(net.ParseIP("2001:db8::1"), nil),
				net.IPv6len,
				net.IP{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
			{
				newIP(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)),
				net.IPv6len,
				net.IP{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
			{
				newIP(nil, nil),
				0,
				nil,
			},
		}

		for _, test := range testCases {
			Expect(test.ip.ToIP()).To(HaveLen(test.expectedLen))
			Expect(test.ip.ToIP()).To(Equal(test.expectedIP))
		}
	})

	It("Encode", func() {
		testCases := []struct {
			object   interface{}
			expected string
		}{
			{
				newIP(net.IPv4(192, 168, 0, 1), net.IPv4Mask(255, 255, 255, 0)),
				`"192.168.0.1/24"`,
			},
			{
				newIP(net.IPv4(192, 168, 0, 2), nil),
				`"192.168.0.2"`,
			},
			{
				newIP(net.ParseIP("2001:db8::1"), nil),
				`"2001:db8::1"`,
			},
			{
				newIP(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)),
				`"2001:db8::1/64"`,
			},
			{
				newIP(nil, nil),
				`""`,
			},
			{
				[]*IP{
					newIP(net.IPv4(192, 168, 0, 1), net.IPv4Mask(255, 255, 255, 0)),
					newIP(net.IPv4(192, 168, 0, 2), nil),
					newIP(net.ParseIP("2001:db8::1"), nil),
					newIP(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)),
					newIP(nil, nil),
				},
				`["192.168.0.1/24","192.168.0.2","2001:db8::1","2001:db8::1/64",""]`,
			},
		}

		for _, test := range testCases {
			bytes, err := json.Marshal(test.object)

			Expect(err).NotTo(HaveOccurred())
			Expect(string(bytes)).To(Equal(test.expected))
		}
	})

	Context("Decode", func() {
		It("valid IP", func() {
			testCases := []struct {
				text     string
				expected *IP
			}{
				{
					`"192.168.0.1"`,
					newIP(net.IPv4(192, 168, 0, 1), nil),
				},
				{
					`"192.168.0.1/24"`,
					newIP(net.IPv4(192, 168, 0, 1), net.IPv4Mask(255, 255, 255, 0)),
				},
				{
					`"2001:db8::1"`,
					newIP(net.ParseIP("2001:db8::1"), nil),
				},
				{
					`"2001:db8::1/64"`,
					newIP(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)),
				},
			}

			for _, test := range testCases {
				ip := &IP{}
				err := json.Unmarshal([]byte(test.text), ip)

				Expect(err).NotTo(HaveOccurred())
				Expect(ip).To(Equal(test.expected))
			}
		})

		It("empty text", func() {
			ip := &IP{}
			err := json.Unmarshal([]byte(`""`), ip)

			Expect(err).NotTo(HaveOccurred())
			Expect(ip).To(Equal(newIP(nil, nil)))
		})

		It("invalid IP", func() {
			testCases := []struct {
				text        string
				expectedErr error
			}{
				{
					`"192.168.0.1000"`,
					fmt.Errorf("invalid IP address 192.168.0.1000"),
				},
				{
					`"2001:db8::1/256"`,
					fmt.Errorf("invalid IP address 2001:db8::1/256"),
				},
				{
					`"test"`,
					fmt.Errorf("invalid IP address test"),
				},
			}

			for _, test := range testCases {
				err := json.Unmarshal([]byte(test.text), &IP{})

				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(test.expectedErr))
			}
		})

		It("IP slice", func() {
			testCases := []struct {
				text     string
				expected []*IP
			}{
				{
					`["192.168.0.1/24","192.168.0.2","2001:db8::1","2001:db8::1/64",""]`,
					[]*IP{
						newIP(net.IPv4(192, 168, 0, 1), net.IPv4Mask(255, 255, 255, 0)),
						newIP(net.IPv4(192, 168, 0, 2), nil),
						newIP(net.ParseIP("2001:db8::1"), nil),
						newIP(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)),
						newIP(nil, nil),
					},
				},
			}

			for _, test := range testCases {
				ips := make([]*IP, 0)
				err := json.Unmarshal([]byte(test.text), &ips)

				Expect(err).NotTo(HaveOccurred())
				Expect(ips).To(Equal(test.expected))
			}
		})
	})
})
