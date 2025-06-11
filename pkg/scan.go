package scanner

import (
	"errors"
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/v3/lib/reporting"

	"github.com/checkmarx/2ms/v3/cmd"
	"github.com/checkmarx/2ms/v3/engine"
)

type ScanConfig struct {
	IgnoreResultIds []string
	IgnoreRules     []string
	WithValidation  bool
}

type scanner struct{}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Scan(scanItems []ScanItem, scanConfig ScanConfig) (*reporting.Report, error) {
	itemsCh := cmd.Channels.Items
	errorsCh := cmd.Channels.Errors
	bufferedErrors := make(chan error, len(scanItems)+1)
	wg := &sync.WaitGroup{}

	// Error listener
	go func() {
		for err := range errorsCh {
			if err != nil {
				bufferedErrors <- err
			}
		}
		close(bufferedErrors)
	}()

	// Initialize engine
	engineConfig := engine.EngineConfig{
		IgnoredIds: scanConfig.IgnoreResultIds,
		IgnoreList: scanConfig.IgnoreRules,
	}
	engineInstance, err := engine.Init(engineConfig)
	if err != nil {
		return &reporting.Report{}, fmt.Errorf("error initializing engine: %w", err)
	}

	// Start processing pipeline
	startPipeline(engineInstance, scanConfig.WithValidation)

	// Send scan items
	for _, item := range scanItems {
		wg.Add(1)
		go func(si ScanItem) {
			defer wg.Done()
			itemsCh <- si
		}(item)
	}
	wg.Wait()
	close(itemsCh)

	// Wait for all processing
	cmd.Channels.WaitGroup.Wait()
	close(errorsCh)

	// Collect errors
	var errs []error
	for err = range bufferedErrors {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return &reporting.Report{}, fmt.Errorf("error(s) processing scan items:\n%w", errors.Join(errs...))
	}

	return cmd.Report, nil
}

func startPipeline(engineInstance engine.IEngine, withValidation bool) {
	cmd.Channels.WaitGroup.Add(4)

	go cmd.ProcessItems(engineInstance, "custom")

	if withValidation {
		go cmd.ProcessSecretsWithValidation()
		go cmd.ProcessValidationAndScoreWithValidation(engineInstance)
	} else {
		go cmd.ProcessSecrets()
		go cmd.ProcessScoreWithoutValidation(engineInstance)
	}

	go cmd.ProcessSecretsExtras()
}

func (s *scanner) ScanDynamic(itemsIn <-chan ScanItem, scanConfig ScanConfig) (*reporting.Report, error) {
	itemsCh := cmd.Channels.Items
	errorsCh := cmd.Channels.Errors

	// Initialize engine configuration.
	engineConfig := engine.EngineConfig{IgnoredIds: scanConfig.IgnoreResultIds, IgnoreList: scanConfig.IgnoreRules}
	engineInstance, err := engine.Init(engineConfig)
	if err != nil {
		return &reporting.Report{}, fmt.Errorf("error initializing engine: %w", err)
	}

	// Start processing routines.
	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessItems(engineInstance, "custom")

	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessSecrets()

	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessSecretsExtras()

	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessScoreWithoutValidation(engineInstance)

	for item := range itemsIn {
		itemsCh <- item
	}
	close(itemsCh)

	// Wait for all processing routines.
	cmd.Channels.WaitGroup.Wait()
	close(errorsCh)

	// Check if any error occurred.
	for err := range errorsCh {
		if err != nil {
			return &reporting.Report{}, fmt.Errorf("error processing scan items: %w", err)
		}
	}

	// Finalize and generate report.
	report := cmd.Report
	return report, nil
}
