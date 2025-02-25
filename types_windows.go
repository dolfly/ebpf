package ebpf

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/platform"
)

// ProgramTypeForGUID resolves a GUID to a ProgramType.
func ProgramTypeForGUID(guid string) (ProgramType, error) {
	parsedGUID, err := windows.GUIDFromString(guid)
	if err != nil {
		return 0, fmt.Errorf("parse GUID: %w", err)
	}

	rawProgramType, err := efw.EbpfGetBpfProgramType(parsedGUID)
	if err != nil {
		return 0, err
	}

	return ProgramTypeForPlatform(platform.Windows, rawProgramType)
}

// AttachTypeForGUID resolves a GUID to an AttachType.
func AttachTypeForGUID(guid string) (AttachType, error) {
	parsedGUID, err := windows.GUIDFromString(guid)
	if err != nil {
		return 0, fmt.Errorf("parse GUID: %w", err)
	}

	rawAttachType, err := efw.EbpfGetBpfAttachType(parsedGUID)
	if err != nil {
		return 0, err
	}

	return AttachTypeForPlatform(platform.Windows, rawAttachType)
}
