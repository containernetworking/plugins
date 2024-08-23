// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package integration_test

import (
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "integration")
}

var echoServerBinaryPath, echoClientBinaryPath string

var _ = SynchronizedBeforeSuite(func() []byte {
	serverBinaryPath, err := gexec.Build("github.com/containernetworking/plugins/pkg/testutils/echo/server")
	Expect(err).NotTo(HaveOccurred())
	clientBinaryPath, err := gexec.Build("github.com/containernetworking/plugins/pkg/testutils/echo/client")
	Expect(err).NotTo(HaveOccurred())
	return []byte(strings.Join([]string{serverBinaryPath, clientBinaryPath}, ","))
}, func(data []byte) {
	binaries := strings.Split(string(data), ",")
	echoServerBinaryPath = binaries[0]
	echoClientBinaryPath = binaries[1]
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
})
