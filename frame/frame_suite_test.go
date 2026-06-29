package frame_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestFrame(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Frame Suite")
}
