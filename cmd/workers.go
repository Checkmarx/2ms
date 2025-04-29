package cmd

import (
	"context"
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/engine/extra"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/shirou/gopsutil/mem"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
)

func ProcessItems(engineInstance *engine.Engine, pluginName string) {
	defer Channels.WaitGroup.Done()

	g, ctx := errgroup.WithContext(context.Background())
	memoryBudget := chooseMemoryBudget()
	sem := semaphore.NewWeighted(memoryBudget)
	for item := range Channels.Items {
		Report.TotalItemsScanned++
		item := item

		switch pluginName {
		case "filesystem":
			g.Go(func() error {
				return engineInstance.DetectFile(ctx, item, SecretsChan, memoryBudget, sem)
			})
		default:
			g.Go(func() error {
				return engineInstance.Detect(item, SecretsChan)
			})
		}
	}

	if err := g.Wait(); err != nil {
		Channels.Errors <- err
	}
	close(SecretsChan)
}

func ProcessSecrets() {
	defer Channels.WaitGroup.Done()

	for secret := range SecretsChan {
		Report.TotalSecretsFound++
		SecretsExtrasChan <- secret
		if validateVar {
			ValidationChan <- secret
		} else {
			CvssScoreWithoutValidationChan <- secret
		}
		Report.Results[secret.ID] = append(Report.Results[secret.ID], secret)
	}
	close(SecretsExtrasChan)
	close(ValidationChan)
	close(CvssScoreWithoutValidationChan)
}

func ProcessSecretsExtras() {
	defer Channels.WaitGroup.Done()

	wgExtras := &sync.WaitGroup{}
	for secret := range SecretsExtrasChan {
		wgExtras.Add(1)
		go extra.AddExtraToSecret(secret, wgExtras)
	}
	wgExtras.Wait()
}

func ProcessValidationAndScoreWithValidation(engine *engine.Engine) {
	defer Channels.WaitGroup.Done()

	wgValidation := &sync.WaitGroup{}
	for secret := range ValidationChan {
		wgValidation.Add(2)
		go func(secret *secrets.Secret, wg *sync.WaitGroup) {
			engine.RegisterForValidation(secret, wg)
			engine.Score(secret, true, wg)
		}(secret, wgValidation)
	}
	wgValidation.Wait()

	engine.Validate()
}

func ProcessScoreWithoutValidation(engine *engine.Engine) {
	defer Channels.WaitGroup.Done()

	wgScore := &sync.WaitGroup{}
	for secret := range CvssScoreWithoutValidationChan {
		wgScore.Add(1)
		go engine.Score(secret, false, wgScore)
	}
	wgScore.Wait()
}

// getCgroupMemoryLimit returns the memory cap imposed by cgroups in bytes
func getCgroupMemoryLimit() uint64 {
	// Try cgroup v2: unified hierarchy
	if data, err := ioutil.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" {
			if v, err := strconv.ParseUint(s, 10, 64); err == nil {
				return v
			}
		}
	}
	// Fallback cgroup v1
	if data, err := ioutil.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
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
