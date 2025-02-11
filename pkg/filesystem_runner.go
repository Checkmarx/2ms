package runner

import (
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/cmd"
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/lib/config"
	"github.com/checkmarx/2ms/lib/reporting"
	"github.com/checkmarx/2ms/plugins"
	"github.com/rs/zerolog/log"
)

type fileSystemRunner struct{}

func NewFileSystemRunner() FileSystemRunner {
	return &fileSystemRunner{}
}

func (r *fileSystemRunner) Run(path string, projectName string, ignored []string) error {
	plugin := &plugins.FileSystemPlugin{
		Path:        path,
		ProjectName: projectName,
		Ignored:     ignored,
	}

	items := cmd.Channels.Items
	errors := cmd.Channels.Errors
	wg := &sync.WaitGroup{}

	// Initialize engine configuration
	engineConfig := engine.EngineConfig{}
	engineInstance, err := engine.Init(engineConfig)
	if err != nil {
		return fmt.Errorf("error initializing engine: %w", err)
	}

	// Add custom regex rules if any
	customRegexRules := []string{}
	if err := engineInstance.AddRegexRules(customRegexRules); err != nil {
		return fmt.Errorf("error adding custom regex rules: %w", err)
	}

	// Start processing items
	wg.Add(1)
	go cmd.ProcessItems(engineInstance, plugin.GetName())

	// Start processing secrets
	wg.Add(1)
	go cmd.ProcessSecrets()

	// Start processing secrets extras
	wg.Add(1)
	go cmd.ProcessSecretsExtras()

	// Start validation and scoring
	validate := false
	if validate {
		wg.Add(1)
		go cmd.ProcessValidationAndScoreWithValidation(engineInstance)
	} else {
		wg.Add(1)
		go cmd.ProcessScoreWithoutValidation(engineInstance)
	}

	// Run the plugin to get files
	go plugin.GetFiles(items, errors, wg)

	// Handle items and errors
	for {
		select {
		case item, ok := <-items:
			if !ok {
				items = nil
			} else {
				fmt.Println("Item:", item)
			}
		case err, ok := <-errors:
			if !ok {
				errors = nil
			} else {
				fmt.Println("Error:", err)
			}
		}

		if items == nil && errors == nil {
			break
		}
	}

	wg.Wait()

	// Finalize and generate report
	report := reporting.Init()
	cfg := config.LoadConfig("2ms", "0.0.0")
	if report.TotalItemsScanned > 0 {
		if err := report.ShowReport("yaml", cfg); err != nil {
			return fmt.Errorf("error showing report: %w", err)
		}

		reportPaths := []string{}
		if len(reportPaths) > 0 {
			if err := report.WriteFile(reportPaths, cfg); err != nil {
				return fmt.Errorf("error writing report file: %w", err)
			}
		}
	} else {
		log.Info().Msg("Scan completed with empty content")
	}

	return nil
}
