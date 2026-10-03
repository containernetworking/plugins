// Copyright 2016 CNI authors
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

// This is a "meta-plugin". It reads in its own netconf, it does not create
// any network interface but just changes the network sysctl.

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/coreos/go-iptables/iptables"
	. "github.com/onsi/ginkgo/v2"

	"github.com/containernetworking/cni/libcni"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

// Exercise the actual chained plugins and packets, not only generated rules.
var _ = DescribeTable("published ports across bridges", func(enabled bool) {
	t := GinkgoT()
	root, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close(); _ = testutils.UnmountNS(root) })
	cni := libcni.NewCNIConfigWithCacheDir(filepath.SplitList(os.Getenv("PATH")), t.TempDir(), nil)
	var serverNS ns.NetNS
	dataDir := t.TempDir()
	create := func(id, name, subnet string, published bool) (ns.NetNS, *current.Result) {
		target, err := testutils.NewNS()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = target.Close(); _ = testutils.UnmountNS(target) })
		text := fmt.Sprintf(`{"cniVersion":"1.0.0","name":%q,"plugins":[
                  {"type":"bridge","bridge":%q,"isGateway":true,"ipMasq":true,"ipam":{"type":"host-local","dataDir":%q,"ranges":[[{"subnet":%q}]],"routes":[{"dst":"0.0.0.0/0"}]}},
                  {"type":"portmap","capabilities":{"portMappings":true}},
                  {"type":"firewall","backend":"iptables","ingressPolicy":"same-bridge","allowPublishedPorts":%t,"capabilities":{"portMappings":true}}
                ]}`, name, name, dataDir, subnet, enabled)
		conf, err := libcni.ConfListFromBytes([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		runtime := &libcni.RuntimeConf{ContainerID: id, NetNS: target.Path(), IfName: "eth0"}
		if published {
			runtime.CapabilityArgs = map[string]interface{}{"portMappings": []map[string]interface{}{{"hostPort": 18090, "containerPort": 8080, "protocol": "tcp"}}}
		}
		var result *current.Result
		err = root.Do(func(ns.NetNS) error {
			raw, e := cni.AddNetworkList(context.Background(), conf, runtime)
			if e != nil {
				return e
			}
			result, e = current.NewResultFromResult(raw)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = root.Do(func(ns.NetNS) error { return cni.DelNetworkList(context.Background(), conf, runtime) })
		})
		return target, result
	}
	serverNS, server := create("server", "ppserver", "10.88.3.0/24", true)
	clientNS, _ := create("client", "ppclient", "10.88.4.0/24", false)
	var listener net.Listener
	err = serverNS.Do(func(ns.NetNS) error {
		var e error
		listener, e = net.Listen("tcp", "0.0.0.0:8080")
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "published-port-ok") }), ReadHeaderTimeout: time.Second}
	go func() { _ = httpServer.Serve(listener) }()
	t.Cleanup(func() { _ = httpServer.Close() })
	request := func(label string, source ns.NetNS, address string, want bool) {
		t.Helper()
		transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			var conn net.Conn
			err := source.Do(func(ns.NetNS) error {
				var e error
				conn, e = (&net.Dialer{}).DialContext(ctx, network, address)
				return e
			})
			return conn, err
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 500 * time.Millisecond}
		response, e := client.Get("http://" + address)
		ok := false
		if e == nil {
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			ok = readErr == nil && string(body) == "published-port-ok"
		}
		if ok != want {
			t.Fatalf("%s: reachable=%t want=%t error=%v", label, ok, want, e)
		}
	}
	host := server.IPs[0].Gateway.String()
	endpoint := server.IPs[0].Address.IP.String()
	request("host control", root, host+":18090", true)
	request("published port", clientNS, host+":18090", enabled)
	request("direct access", clientNS, endpoint+":8080", false)
	// A later bridge ADD must not put a DROP ahead of reply exceptions.
	laterNS, _ := create("later", "pplater", "10.88.5.0/24", false)
	request("later bridge", laterNS, host+":18090", enabled)
	request("original bridge after ADD", clientNS, host+":18090", enabled)
	err = root.Do(func(ns.NetNS) error {
		ipt, e := iptables.New()
		if e != nil {
			return e
		}
		return ipt.Insert("nat", "PREROUTING", 1, "-d", host, "-p", "tcp", "--dport", "18091", "-j", "DNAT", "--to-destination", endpoint+":8080")
	})
	if err != nil {
		t.Fatal(err)
	}
	request("unrelated DNAT", clientNS, host+":18091", false)
	if enabled {
		err = root.Do(func(ns.NetNS) error {
			ipt, e := iptables.New()
			if e != nil {
				return e
			}
			return ipt.Insert("filter", "CNI-ADMIN", 1, "-d", endpoint, "-p", "tcp", "--dport", "8080", "-j", "DROP")
		})
		if err != nil {
			t.Fatal(err)
		}
		request("administrator DROP", clientNS, host+":18090", false)
	}
}, Entry("disabled", false), Entry("enabled", true))
