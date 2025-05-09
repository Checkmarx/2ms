package cmd

import (
	"os"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/mem"
)

// getCgroupMemoryLimit returns the memory cap imposed by cgroups in bytes
func getCgroupMemoryLimit() uint64 {
	// Try cgroup v2: unified hierarchy
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" {
			if v, err := strconv.ParseUint(s, 10, 64); err == nil {
				return v
			}
		}
	}
	// Fallback cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			return v
		}
	}
	// No limit detected
	return ^uint64(0) // max uint64
}

// getTotalMemory returns the total physical RAM in bytes
func getTotalMemory() uint64 {
	if vm, err := mem.VirtualMemory(); err == nil {
		return vm.Total
	}
	return ^uint64(0) // max uint64
}

// chooseMemoryBudget picks 50% of total RAM (but at least 256 MiB)
func chooseMemoryBudget() int64 {
	// Physical RAM
	totalHost := getTotalMemory()

	// Cgroup limit
	cgroupLimit := getCgroupMemoryLimit()

	// Effective total = min(host, cgroup)
	var effectiveTotal uint64
	if totalHost < cgroupLimit {
		effectiveTotal = totalHost
	} else {
		effectiveTotal = cgroupLimit
	}

	// use 50% but cap to [256 MiB -> total − safety margin]
	safetyMargin := uint64(200 * 1024 * 1024) // reserve 200 MiB for OS/other processes
	avail := effectiveTotal
	if effectiveTotal > safetyMargin {
		avail = effectiveTotal - safetyMargin
	}
	budget := int64(avail / 2) // use half of what remains
	if budget < 256*1024*1024 {
		budget = 256 * 1024 * 1024
	}
	return budget
}
