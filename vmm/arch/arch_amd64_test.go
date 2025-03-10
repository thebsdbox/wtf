//go:build linux && amd64

package arch_test

import (
	"os"
	"testing"

	"github.com/vm-tools/wtf/vmm/arch"
)

func TestMMIOHole(t *testing.T) {
	sys, err := os.Open("/dev/kvm")
	if err != nil {
		t.Fatal(err)
	}

	defer sys.Close()

	a, err := arch.New(sys)
	if err != nil {
		t.Fatal(err)
	}

	// too big for a single region
	mem := make([]byte, arch.MMIOHoleAddr+os.Getpagesize())

	rr, err := a.SetupMemory(mem)
	if err != nil {
		t.Fatal(err)
	}

	if len(rr) != 2 {
		t.Fatalf("len(rr) %d != 2", len(rr))
	}
}
