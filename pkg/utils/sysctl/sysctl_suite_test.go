package sysctl_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSysctl(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sysctl Suite")
}
