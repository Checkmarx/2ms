package semaphore

//go:generate mockgen -source=$GOFILE -destination=${GOPACKAGE}_mock.go -package=${GOPACKAGE}

import (
	"context"
	"fmt"
	"github.com/shirou/gopsutil/mem"
	"golang.org/x/sync/semaphore"
	"os"
	"strconv"
	"strings"
)

type Semaphore struct {
	memoryBudget int64
	sem          *semaphore.Weighted
}

type ISemaphore interface {
	AcquireMemoryWeight(ctx context.Context, weight int64) error
	ReleaseMemoryWeight(weight int64)
}

func NewSemaphore() *Semaphore {
	b := chooseMemoryBudget()
	return NewSemaphoreWithBudget(b)
}

func NewSemaphoreWithBudget(b int64) *Semaphore {
	return &Semaphore{
		memoryBudget: b,
		sem:          semaphore.NewWeighted(b),
	}
}

// AcquireMemoryWeight acquires semaphore with a specified weight
func (s *Semaphore) AcquireMemoryWeight(ctx context.Context, weight int64) error {
	if weight > s.memoryBudget {
		return fmt.Errorf("buffer size %d exceeds memory budget %d", weight, s.memoryBudget)
	}
	if err := s.sem.Acquire(ctx, weight); err != nil {
		return fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	return nil
}

// ReleaseMemoryWeight releases semaphore with a specified weight
func (s *Semaphore) ReleaseMemoryWeight(weight int64) {
	s.sem.Release(weight)
}

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

// computeMemoryBudget computes the memory budget based on the host memory and cgroup limits
func computeMemoryBudget(totalHost, cgroupLimit uint64) int64 {
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

// chooseMemoryBudget picks 50% of total RAM (but at least 256 MiB)
func chooseMemoryBudget() int64 {
	// Physical RAM
	totalHost := getTotalMemory()
	// Cgroup limit
	cgroupLimit := getCgroupMemoryLimit()

	return computeMemoryBudget(totalHost, cgroupLimit)
}
