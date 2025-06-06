package scanner

import (
	"errors"
	"fmt"
	"github.com/checkmarx/2ms/lib/reporting"
	"sync"

	"github.com/checkmarx/2ms/cmd"
	"github.com/checkmarx/2ms/engine"
)

type ScanConfig struct {
	IgnoreResultIds []string
	IgnoreRules     []string
}

type scanner struct{}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Scan(scanItems []ScanItem, scanConfig ScanConfig) (*reporting.Report, error) {
	itemsCh := cmd.Channels.Items
	errorsCh := cmd.Channels.Errors
	wg := &sync.WaitGroup{}

	// listener for errors
	bufferedErrors := make(chan error, len(scanItems)+1)
	go func() {
		for err := range errorsCh {
			if err != nil {
				bufferedErrors <- err
			}
		}
		close(bufferedErrors)
	}()

	// Initialize engine configuration
	engineConfig := engine.EngineConfig{IgnoredIds: scanConfig.IgnoreResultIds, IgnoreList: scanConfig.IgnoreRules}
	engineInstance, err := engine.Init(engineConfig)
	if err != nil {
		return &reporting.Report{}, fmt.Errorf("error initializing engine: %w", err)
	}

	// Start processing items
	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessItems(engineInstance, "custom")

	// Start processing secrets
	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessSecrets()

	// Start processing secrets extras
	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessSecretsExtras()

	// Start validation and scoring
	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessScoreWithoutValidation(engineInstance)

	// send items to be scanned
	for _, scanItem := range scanItems {
		wg.Add(1)
		go func(item ScanItem) {
			defer wg.Done()
			itemsCh <- item
		}(scanItem)
	}
	wg.Wait()
	close(itemsCh)
	cmd.Channels.WaitGroup.Wait()

	close(errorsCh)
	var errs []error
	for err = range bufferedErrors {
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return &reporting.Report{}, fmt.Errorf("error(s) processing scan items:\n%w", errors.Join(errs...))
	}

	// Finalize and generate report
	report := cmd.Report
	return report, nil
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
