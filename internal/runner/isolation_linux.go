//go:build linux

package runner

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
)

// CheckIsolation verifies kernel-visible protections inside the trusted runner.
func CheckIsolation(limits Limits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	if os.Getuid() != 65532 || os.Geteuid() != 65532 {
		return errors.New("runner must use its unprivileged UID")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			fields[strings.TrimSuffix(parts[0], ":")] = parts[1]
		}
	}
	if fields["CapEff"] != "0000000000000000" || fields["CapBnd"] != "0000000000000000" || fields["NoNewPrivs"] != "1" || fields["Seccomp"] != "2" {
		return errors.New("runner capability or syscall protection missing")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			return errors.New("runner has an external network interface")
		}
	}
	readLimit := func(file string) (int64, error) {
		raw, err := os.ReadFile("/sys/fs/cgroup/" + file)
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	}
	memory, err := readLimit("memory.max")
	if err != nil || memory <= 0 || memory > limits.MemoryBytes {
		return errors.New("memory cgroup limit missing")
	}
	swap, err := readLimit("memory.swap.max")
	if err != nil || swap != 0 {
		return errors.New("swap must be disabled")
	}
	pids, err := readLimit("pids.max")
	if err != nil || pids <= 0 || pids > int64(limits.PIDs) {
		return errors.New("PID cgroup limit missing")
	}
	cpu, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return err
	}
	parts := strings.Fields(string(cpu))
	if len(parts) != 2 {
		return errors.New("CPU limit missing")
	}
	quota, e1 := strconv.ParseInt(parts[0], 10, 64)
	period, e2 := strconv.ParseInt(parts[1], 10, 64)
	if e1 != nil || e2 != nil || quota <= 0 || period <= 0 || quota > period*limits.CPUMillis/1000 {
		return errors.New("CPU cgroup limit missing")
	}
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return err
	}
	rootRO, tmpOK := false, false
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		options := strings.Split(f[3], ",")
		has := func(want string) bool {
			for _, v := range options {
				if v == want {
					return true
				}
			}
			return false
		}
		if f[1] == "/" {
			rootRO = has("ro")
		}
		if f[1] == "/tmp" && f[2] == "tmpfs" && has("noexec") && has("nosuid") && has("nodev") {
			for _, v := range options {
				if strings.HasPrefix(v, "size=") {
					size := strings.TrimPrefix(v, "size=")
					mult := int64(1)
					if strings.HasSuffix(size, "k") {
						mult = 1024
						size = strings.TrimSuffix(size, "k")
					}
					n, e := strconv.ParseInt(size, 10, 64)
					tmpOK = e == nil && n > 0 && n <= limits.TmpBytes/mult
				}
			}
		}
	}
	if !rootRO || !tmpOK {
		return errors.New("read-only root or bounded scratch mount missing")
	}
	return nil
}
