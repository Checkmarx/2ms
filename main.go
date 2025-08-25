package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"
	"time"

	"github.com/checkmarx/2ms/v3/cmd"
	"github.com/checkmarx/2ms/v3/lib/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = utils.CreateLogger(zerolog.InfoLevel)

	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit gitleaks
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	// Start CPU, trace, and allocs profiling for entire app duration
	// timestamp := time.Now().Format("20060102_150405")
	// startCPUProfile(timestamp)
	// startTraceProfile(timestamp)

	// Start heap profiling ticker
	// go startHeapProfiling()

	// Start memory stats ticker
	go printMemoryStats()

	cmd.Execute()

	// stopCPUProfile()
	// stopTraceProfile()
	// writeAllocsProfile(timestamp)

	cmd.Exit(0, nil)

}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	log.Fatal().Msg("Interrupt signal received. Exiting...") // lint:ignore We want to exit immediately
}

func printMemoryStats() {
	fmt.Println("Printing memory stats")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		// Convert bytes to MB for better readability
		allocMB := uint64(m.Alloc / 1024 / 1024)
		totalAllocMB := uint64(m.TotalAlloc / 1024 / 1024)
		sysMB := uint64(m.Sys / 1024 / 1024)
		heapAllocMB := uint64(m.HeapAlloc / 1024 / 1024)
		heapSysMB := uint64(m.HeapSys / 1024 / 1024)

		log.Info().
			Str("header", "=== MEMORY STATISTICS ===").
			Send()
		log.Info().
			Str("category", "GENERAL_MEMORY").
			Uint64("ALLOC_MB", allocMB).
			Uint64("TOTAL_ALLOC_MB", totalAllocMB).
			Uint64("SYS_MB", sysMB).
			Send()
		log.Info().
			Str("category", "HEAP_MEMORY").
			Uint64("HEAP_ALLOC_MB", heapAllocMB).
			Uint64("HEAP_SYS_MB", heapSysMB).
			Uint64("HEAP_IDLE_MB", m.HeapIdle/1024/1024).
			Uint64("HEAP_INUSE_MB", m.HeapInuse/1024/1024).
			Uint64("HEAP_RELEASED_MB", m.HeapReleased/1024/1024).
			Send()
		log.Info().
			Str("category", "ALLOCATION_STATS").
			Uint64("MALLOCS", m.Mallocs).
			Uint64("FREES", m.Frees).
			Uint64("LOOKUPS", m.Lookups).
			Send()
		log.Info().
			Str("category", "RUNTIME_STATS").
			Uint64("STACK_INUSE_MB", m.StackInuse/1024/1024).
			Uint64("MSPAN_INUSE_MB", m.MSpanInuse/1024/1024).
			Uint64("MCACHE_INUSE_MB", m.MCacheInuse/1024/1024).
			Send()

		// Container memory stats
		containerUsage := GetContainerMemoryStats()
		log.Info().
			Str("category", "CONTAINER_MEMORY").
			Uint64("CONTAINER_USAGE_MB", containerUsage).
			Send()

	}
}

func GetContainerMemoryStats() uint64 {
	// Try cgroups v2 first
	usage := readMemoryUsageV2()
	if usage == 0 {
		usage = readMemoryUsageV1()
	}
	// Convert bytes to MB
	return usage / 1024 / 1024
}

func readMemoryUsageV2() uint64 {
	data, _ := os.ReadFile("/sys/fs/cgroup/memory.current")
	if len(data) == 0 {
		return 0
	}
	val, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return val
}

func readMemoryUsageV1() uint64 {
	data, _ := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes")
	if len(data) == 0 {
		return 0
	}
	val, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return val
}

var cpuFile *os.File
var traceFile *os.File

func startCPUProfile(timestamp string) {
	// Ensure profiling directory exists
	if err := os.MkdirAll("profiling_2ms", 0755); err != nil {
		log.Error().Err(err).Msg("Failed to create profiling directory")
		return
	}

	var err error
	filename := fmt.Sprintf("profiling_2ms/cpu_profile_%s.prof", timestamp)
	cpuFile, err = os.Create(filename)
	if err != nil {
		log.Error().Err(err).Str("filename", filename).Msg("Failed to create CPU profile file")
		return
	}
	log.Info().Str("filename", filename).Msg("Created CPU profile file")

	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		log.Error().Err(err).Msg("Failed to start CPU profile")
		cpuFile.Close()
		cpuFile = nil
		return
	}
	log.Info().Msg("CPU profiling started successfully")
}

func stopCPUProfile() {
	pprof.StopCPUProfile()
	if cpuFile != nil {
		// Get file info before closing
		if stat, err := cpuFile.Stat(); err == nil {
			log.Info().Int64("file_size_bytes", stat.Size()).Str("filename", stat.Name()).Msg("CPU profile file info")
		}
		cpuFile.Close()
		cpuFile = nil
	}
	log.Info().Msg("CPU profiling stopped")
}

func startTraceProfile(timestamp string) {
	// Ensure profiling directory exists
	if err := os.MkdirAll("profiling_2ms", 0755); err != nil {
		log.Error().Err(err).Msg("Failed to create profiling directory")
		return
	}

	var err error
	filename := fmt.Sprintf("profiling_2ms/trace_profile_%s.trace", timestamp)
	traceFile, err = os.Create(filename)
	if err != nil {
		log.Error().Err(err).Str("filename", filename).Msg("Failed to create trace profile file")
		return
	}
	log.Info().Str("filename", filename).Msg("Created trace profile file")

	if err := trace.Start(traceFile); err != nil {
		log.Error().Err(err).Msg("Failed to start trace profile")
		traceFile.Close()
		traceFile = nil
		return
	}
	log.Info().Msg("Trace profiling started successfully")
}

func stopTraceProfile() {
	trace.Stop()
	if traceFile != nil {
		// Get file info before closing
		if stat, err := traceFile.Stat(); err == nil {
			log.Info().Int64("file_size_bytes", stat.Size()).Str("filename", stat.Name()).Msg("Trace profile file info")
		}
		traceFile.Close()
		traceFile = nil
	}
	log.Info().Msg("Trace profiling stopped")
}

func writeAllocsProfile(timestamp string) {
	// Ensure profiling directory exists
	if err := os.MkdirAll("profiling_2ms", 0755); err != nil {
		log.Error().Err(err).Msg("Failed to create profiling directory")
		return
	}

	allocsFile, err := os.Create(fmt.Sprintf("profiling_2ms/allocs_profile_%s.prof", timestamp))
	if err != nil {
		log.Error().Err(err).Msg("Failed to create allocs profile file")
		return
	}
	defer allocsFile.Close()

	if profile := pprof.Lookup("allocs"); profile != nil {
		if err := profile.WriteTo(allocsFile, 0); err != nil {
			log.Error().Err(err).Msg("Failed to write allocs profile")
			return
		}
	}
	log.Info().Msg("Allocs profile saved")
}

func startHeapProfiling() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		timestamp := time.Now().Format("20060102_150405")

		// Ensure profiling directory exists
		if err := os.MkdirAll("profiling_2ms", 0755); err != nil {
			log.Error().Err(err).Msg("Failed to create profiling directory")
			continue
		}

		heapFile, err := os.Create(fmt.Sprintf("profiling_2ms/heap_profile_%s.prof", timestamp))
		if err != nil {
			log.Error().Err(err).Msg("Failed to create heap profile file")
			continue
		}
		runtime.GC()
		if err := pprof.WriteHeapProfile(heapFile); err != nil {
			log.Error().Err(err).Msg("Failed to write heap profile")
		}
		heapFile.Close()

		log.Info().Str("timestamp", timestamp).Msg("Heap profile saved")
	}
}
