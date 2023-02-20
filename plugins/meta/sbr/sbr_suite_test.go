// The boilerplate needed for Ginkgo

package main

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestSample(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "plugins/sbr")
}
