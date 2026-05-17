//go:build linux

package runner

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// newProcAttr puts the child in its own process group so watchMem
// can SIGKILL the whole tree (most scanners fork helpers).
func newProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
		// Pdeathsig=SIGKILL: if the agent process exits, the kernel
		// kills the scanner subprocess too. Prevents orphaned
		// runaway scanners after an agent crash.
		Pdeathsig: syscall.SIGKILL,
	}
}

// watchMem polls /proc/<pid>/status every 2s and kills the process
// group if VmRSS exceeds maxMemMiB. Exits when ctx is cancelled or
// the process disappears.
func watchMem(ctx context.Context, pid int, maxMemMiB int) {
	limitKB := uint64(maxMemMiB) * 1024
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rss, ok := readVmRSSKB(pid)
			if !ok {
				return // process gone
			}
			if rss > limitKB {
				// Kill the whole process group. Negative PID =
				// process group ID. SIGKILL not SIGTERM — a
				// runaway scanner doesn't deserve graceful.
				_ = syscall.Kill(-pid, syscall.SIGKILL)
				return
			}
		}
	}
}

// readVmRSSKB returns the VmRSS field (in KB) from /proc/<pid>/status,
// or (0, false) if the file can't be read (process gone, perm denied).
func readVmRSSKB(pid int) (uint64, bool) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		// VmRSS:    1234 kB
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb, true
	}
	return 0, false
}
