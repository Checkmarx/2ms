package runner

import (
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/cmd"
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/lib/config"
	"github.com/checkmarx/2ms/plugins"
	"github.com/rs/zerolog/log"
)

type fileSystemRunner struct{}

func NewFileSystemRunner() FileSystemRunner {
	return &fileSystemRunner{}
}

func (r *fileSystemRunner) Run(path string, projectName string, ignored []string) (string, error) {
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
		return "", fmt.Errorf("error initializing engine: %w", err)
	}

	// Add custom regex rules if any
	customRegexRules := []string{}
	if err := engineInstance.AddRegexRules(customRegexRules); err != nil {
		return "", fmt.Errorf("error adding custom regex rules: %w", err)
	}

	// Start processing items
	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessItems(engineInstance, plugin.GetName())

	// Start processing secrets
	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessSecrets()

	// Start processing secrets extras
	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessSecretsExtras()

	// Start validation and scoring
	validate := false
	if validate {
		cmd.Channels.WaitGroup.Add(1)
		go cmd.ProcessValidationAndScoreWithValidation(engineInstance)
	} else {
		cmd.Channels.WaitGroup.Add(1)
		go cmd.ProcessScoreWithoutValidation(engineInstance)
	}

	// Run the plugin to get files
	wg.Add(1)
	go func() {
		plugin.GetFiles(items, errors, wg)
		wg.Done()
	}()
	wg.Wait()
	close(items)
	cmd.Channels.WaitGroup.Wait()

	// Finalize and generate report
	report := cmd.Report
	cfg := config.LoadConfig("2ms", "0.0.0")

	if report.TotalItemsScanned > 0 {
		jsonData, err := report.GetOutput("json", cfg)
		if err != nil {
			return "", fmt.Errorf("error showing report: %w", err)
		}
		return jsonData, nil

	} else {
		log.Info().Msg("Scan completed with empty content")
	}

	return "", nil
}
