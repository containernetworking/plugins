package main_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestFirewalld(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "firewalld Suite")
}
