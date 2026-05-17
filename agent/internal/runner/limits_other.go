//go:build !linux

package runner

import (
	"context"
	"syscall"
)

// newProcAttr is a no-op on non-Linux platforms. Resource limits
// should be enforced externally (cgroups, jobobjects, rctl).
func newProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

// watchMem is a no-op on non-Linux platforms. The agent is supported
// on Linux for production; macOS/Windows builds exist only for local
// dev and don't enforce memory caps.
func watchMem(_ context.Context, _ int, _ int) {}
