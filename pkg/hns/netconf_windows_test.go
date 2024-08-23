// Copyright 2017 CNI authors
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
package hns

import (
	"encoding/json"
	"net"

	"github.com/Microsoft/hcsshim/hcn"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NetConf", func() {
	Describe("ApplyLoopbackDSRPolicy", func() {
		Context("via v1 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{}
			})

			It("filter out duplicated IP", func() {
				// mock duplicated IP
				ip := net.ParseIP("172.16.0.12")
				n.ApplyLoopbackDSRPolicy(&ip)
				n.ApplyLoopbackDSRPolicy(&ip)

				// only one policy
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(1))

				// normal type judgement
				policy := addlArgs[0]
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("Destinations"))

				// and only one item
				destinationList := value["Destinations"].([]interface{})
				Expect(destinationList).Should(HaveLen(1))
				Expect(destinationList[0].(string)).Should(Equal("172.16.0.12"))
			})

			It("append different IP", func() {
				// mock different IP
				ip1 := net.ParseIP("172.16.0.12")
				n.ApplyLoopbackDSRPolicy(&ip1)
				ip2 := net.ParseIP("172.16.0.13")
				n.ApplyLoopbackDSRPolicy(&ip2)

				// will be two policies
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(2))

				// normal type judgement
				policy := addlArgs[1] // pick second item
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("Destinations"))

				// only one item
				destinationList := value["Destinations"].([]interface{})
				Expect(destinationList).Should(HaveLen(1))
				Expect(destinationList[0].(string)).Should(Equal("172.16.0.13"))
			})
		})

		Context("via v2 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{ApiVersion: 2}
			})

			It("filter out duplicated IP", func() {
				// mock duplicated IP
				ip := net.ParseIP("172.16.0.12")
				n.ApplyLoopbackDSRPolicy(&ip)
				n.ApplyLoopbackDSRPolicy(&ip)

				// only one policy
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(1))

				// normal type judgement
				policy := addlArgs[0]
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("Settings"))

				// and only one item
				settings := value["Settings"].(map[string]interface{})
				destinationList := settings["Destinations"].([]interface{})
				Expect(destinationList).Should(HaveLen(1))
				Expect(destinationList[0].(string)).Should(Equal("172.16.0.12"))
			})

			It("append different IP", func() {
				// mock different IP
				ip1 := net.ParseIP("172.16.0.12")
				n.ApplyLoopbackDSRPolicy(&ip1)
				ip2 := net.ParseIP("172.16.0.13")
				n.ApplyLoopbackDSRPolicy(&ip2)

				// will be two policies
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(2))

				// normal type judgement
				policy := addlArgs[1] // pick second item
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("Settings"))

				// only one item
				settings := value["Settings"].(map[string]interface{})
				destinationList := settings["Destinations"].([]interface{})
				Expect(destinationList).Should(HaveLen(1))
				Expect(destinationList[0].(string)).Should(Equal("172.16.0.13"))
			})
		})
	})

	Describe("ApplyOutBoundNATPolicy", func() {
		Context("via v1 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{}
			})

			It("append different IP", func() {
				// mock different IP
				n.ApplyOutboundNatPolicy("192.168.0.0/16")
				n.ApplyOutboundNatPolicy("10.244.0.0/16")

				// will be two policies
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(2))

				// normal type judgement
				policy := addlArgs[1] // pick second item
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("ExceptionList"))

				// but get two items
				exceptionList := value["ExceptionList"].([]interface{})
				Expect(exceptionList).Should(HaveLen(1))
				Expect(exceptionList[0].(string)).Should(Equal("10.244.0.0/16"))
			})

			It("append a new one if there is not an exception OutBoundNAT policy", func() {
				// mock different OutBoundNAT routes
				n.Policies = []Policy{
					{
						Name:  "EndpointPolicy",
						Value: bprintf(`{"Type": "OutBoundNAT", "OtherList": []}`),
					},
				}
				n.ApplyOutboundNatPolicy("10.244.0.0/16")

				// has two policies
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(2))

				// normal type judgement
				policy := addlArgs[0]
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("OtherList"))
				policy = addlArgs[1]
				value = make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("ExceptionList"))

				// only get one item
				exceptionList := value["ExceptionList"].([]interface{})
				Expect(exceptionList).Should(HaveLen(1))
				Expect(exceptionList[0].(string)).Should(Equal("10.244.0.0/16"))
			})

			It("nothing to do if CIDR is blank", func() {
				// mock different OutBoundNAT routes
				n.Policies = []Policy{
					{
						Name:  "EndpointPolicy",
						Value: bprintf(`{"Type": "OutBoundNAT", "ExceptionList": []}`),
					},
				}
				n.ApplyOutboundNatPolicy("")

				// only one policy
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(1))

				// normal type judgement
				policy := addlArgs[0]
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("ExceptionList"))

				// empty list
				Expect(value["ExceptionList"]).ShouldNot(BeNil())
				Expect(value["ExceptionList"]).Should(HaveLen(0))
			})
		})

		Context("via v2 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{ApiVersion: 2}
			})

			It("append different IP", func() {
				// mock different IP
				n.ApplyOutboundNatPolicy("192.168.0.0/16")
				n.ApplyOutboundNatPolicy("10.244.0.0/16")

				// will be two policies
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(2))

				// normal type judgement
				policy := addlArgs[1] // pick second item
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("Settings"))

				// but get two items
				settings := value["Settings"].(map[string]interface{})
				exceptionList := settings["Exceptions"].([]interface{})
				Expect(exceptionList).Should(HaveLen(1))
				Expect(exceptionList[0].(string)).Should(Equal("10.244.0.0/16"))
			})

			It("append a new one if there is not an exception OutBoundNAT policy", func() {
				// mock different OutBoundNAT routes
				n.Policies = []Policy{
					{
						Name:  "EndpointPolicy",
						Value: bprintf(`{"Type": "OutBoundNAT", "Settings": {"Others": []}}`),
					},
				}
				n.ApplyOutboundNatPolicy("10.244.0.0/16")

				// has two policies
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(2))

				// normal type judgement
				policy := addlArgs[0]
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("Settings"))
				Expect(value["Settings"]).Should(HaveKey("Others"))
				policy = addlArgs[1]
				value = make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("Settings"))

				// only get one item
				settings := value["Settings"].(map[string]interface{})
				exceptionList := settings["Exceptions"].([]interface{})
				Expect(exceptionList).Should(HaveLen(1))
				Expect(exceptionList[0].(string)).Should(Equal("10.244.0.0/16"))
			})

			It("nothing to do if CIDR is blank", func() {
				// mock different OutBoundNAT routes
				n.Policies = []Policy{
					{
						Name:  "EndpointPolicy",
						Value: bprintf(`{"Type": "OutBoundNAT", "Settings": {"Exceptions": []}}`),
					},
				}
				n.ApplyOutboundNatPolicy("")

				// only one policy
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(1))

				// normal type judgement
				policy := addlArgs[0]
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("OutBoundNAT"))
				Expect(value).Should(HaveKey("Settings"))

				// empty list
				settings := value["Settings"].(map[string]interface{})
				Expect(settings["Exceptions"]).ShouldNot(BeNil())
				Expect(settings["Exceptions"]).Should(HaveLen(0))
			})
		})
	})

	Describe("ApplyDefaultPAPolicy", func() {
		Context("via v1 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{}
			})

			It("append different IP", func() {
				// mock different IP
				n.ApplyDefaultPAPolicy("192.168.0.1")
				n.ApplyDefaultPAPolicy("192.168.0.2")

				// will be two policies
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(2))

				// normal type judgement
				policy := addlArgs[1] // judge second item
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("PA"))

				// compare with second item
				paAddress := value["PA"].(string)
				Expect(paAddress).Should(Equal("192.168.0.2"))
			})

			It("nothing to do if IP is blank", func() {
				// mock different policy
				n.Policies = []Policy{
					{
						Name:  "EndpointPolicy",
						Value: bprintf(`{"Type": "OutBoundNAT", "Exceptions": ["192.168.0.0/16"]}`),
					},
				}
				n.ApplyDefaultPAPolicy("")

				// nothing
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(1))
			})
		})

		Context("via v2 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{ApiVersion: 2}
			})

			It("append different IP", func() {
				// mock different IP
				n.ApplyDefaultPAPolicy("192.168.0.1")
				n.ApplyDefaultPAPolicy("192.168.0.2")

				// will be two policies
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(2))

				// normal type judgement
				policy := addlArgs[1] // judge second item
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("ProviderAddress"))
				Expect(value).Should(HaveKey("Settings"))

				// compare with second item
				settings := value["Settings"].(map[string]interface{})
				paAddress := settings["ProviderAddress"].(string)
				Expect(paAddress).Should(Equal("192.168.0.2"))
			})

			It("nothing to do if IP is blank", func() {
				// mock different policy
				n.Policies = []Policy{
					{
						Name:  "EndpointPolicy",
						Value: bprintf(`{"Type": "OutBoundNAT", "Settings": {"Exceptions": ["192.168.0.0/16"]}}`),
					},
				}
				n.ApplyDefaultPAPolicy("")

				// nothing
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(1))
			})
		})
	})

	Describe("ApplyPortMappingPolicy", func() {
		Context("via v1 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{}
			})

			It("nothing to do if input is empty", func() {
				n.ApplyPortMappingPolicy(nil)
				Expect(n.Policies).Should(BeNil())

				n.ApplyPortMappingPolicy([]PortMapEntry{})
				Expect(n.Policies).Should(BeNil())
			})

			It("create one NAT policy", func() {
				// mock different IP
				n.ApplyPortMappingPolicy([]PortMapEntry{
					{
						ContainerPort: 80,
						HostPort:      8080,
						Protocol:      "TCP",
						HostIP:        "192.168.1.2",
					},
				})

				// only one item
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(1))

				// normal type judgement
				policy := addlArgs[0]
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("NAT"))

				// compare all values
				Expect(value).Should(HaveKey("InternalPort"))
				Expect(value["InternalPort"]).Should(Equal(float64(80)))
				Expect(value).Should(HaveKey("ExternalPort"))
				Expect(value["ExternalPort"]).Should(Equal(float64(8080)))
				Expect(value).Should(HaveKey("Protocol"))
				Expect(value["Protocol"]).Should(Equal("TCP"))
			})
		})

		Context("via v2 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{ApiVersion: 2}
			})

			It("nothing to do if input is empty", func() {
				n.ApplyPortMappingPolicy(nil)
				Expect(n.Policies).Should(BeNil())

				n.ApplyPortMappingPolicy([]PortMapEntry{})
				Expect(n.Policies).Should(BeNil())
			})

			It("creates one NAT policy", func() {
				// mock different IP
				n.ApplyPortMappingPolicy([]PortMapEntry{
					{
						ContainerPort: 80,
						HostPort:      8080,
						Protocol:      "TCP",
						HostIP:        "192.168.1.2",
					},
				})

				// only one item
				addlArgs := n.Policies
				Expect(addlArgs).Should(HaveLen(1))

				// normal type judgement
				policy := addlArgs[0]
				Expect(policy.Name).Should(Equal("EndpointPolicy"))
				value := make(map[string]interface{})
				json.Unmarshal(policy.Value, &value)
				Expect(value).Should(HaveKey("Type"))
				Expect(value["Type"]).Should(Equal("PortMapping"))
				Expect(value).Should(HaveKey("Settings"))

				// compare all values
				settings := value["Settings"].(map[string]interface{})
				Expect(settings).Should(HaveKey("InternalPort"))
				Expect(settings["InternalPort"]).Should(Equal(float64(80)))
				Expect(settings).Should(HaveKey("ExternalPort"))
				Expect(settings["ExternalPort"]).Should(Equal(float64(8080)))
				Expect(settings).Should(HaveKey("Protocol"))
				Expect(settings["Protocol"]).Should(Equal(float64(6)))
				Expect(settings).Should(HaveKey("VIP"))
				Expect(settings["VIP"]).Should(Equal("192.168.1.2"))
			})
		})
	})

	Describe("GetXEndpointPolicies", func() {
		Context("via v1 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{}
			})

			It("GetHNSEndpointPolicies", func() {
				// mock different policies
				n.Policies = []Policy{
					{
						Name:  "EndpointPolicy",
						Value: []byte(`{"Type": "OutBoundNAT", "ExceptionList": [ "192.168.1.2" ]}`),
					},
					{
						Name:  "someOtherType",
						Value: []byte(`{"someOtherKey": "someOtherValue"}`),
					},
				}

				// only one valid item
				result := n.GetHNSEndpointPolicies()
				Expect(len(result)).To(Equal(1))

				// normal type judgement
				policy := make(map[string]interface{})
				err := json.Unmarshal(result[0], &policy)
				Expect(err).ToNot(HaveOccurred())
				Expect(policy).Should(HaveKey("Type"))
				Expect(policy["Type"]).To(Equal("OutBoundNAT"))
				Expect(policy).Should(HaveKey("ExceptionList"))
				Expect(policy["ExceptionList"]).To(ContainElement("192.168.1.2"))
			})
		})

		Context("via v2 api", func() {
			var n NetConf
			BeforeEach(func() {
				n = NetConf{ApiVersion: 2}
			})

			It("GetHostComputeEndpointPolicies", func() {
				// mock different policies
				n.Policies = []Policy{
					{
						Name:  "EndpointPolicy",
						Value: []byte(`{"Type": "OutBoundNAT", "Settings": {"Exceptions": [ "192.168.1.2" ]}}`),
					},
					{
						Name:  "someOtherType",
						Value: []byte(`{"someOtherKey": "someOtherValue"}`),
					},
				}

				// only one valid item
				result := n.GetHostComputeEndpointPolicies()
				Expect(len(result)).To(Equal(1))

				// normal type judgement
				policy := result[0]
				Expect(policy.Type).Should(Equal(hcn.OutBoundNAT))
				settings := make(map[string]interface{})
				err := json.Unmarshal(policy.Settings, &settings)
				Expect(err).ToNot(HaveOccurred())
				Expect(settings["Exceptions"]).To(ContainElement("192.168.1.2"))
			})
		})
	})
})
