// The boilerplate needed for Ginkgo

package main

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSample(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "plugins/sample")
}
