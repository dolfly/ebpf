//go:build !windows

package ebpf

import (
	"github.com/cilium/ebpf/asm"
)

const fnMapLookupElem = asm.FnMapLookupElem
