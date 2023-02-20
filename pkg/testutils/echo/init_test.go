package main_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestEchosvr(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "pkg/testutils/echosvr")
}
