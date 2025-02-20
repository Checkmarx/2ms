package scanner

import (
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/cmd"
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/lib/config"
	"github.com/rs/zerolog/log"
)

type scanner struct{}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Scan(scanItems []ScanItem) (string, error) {
	items := cmd.Channels.Items
	wg := &sync.WaitGroup{}

	// Initialize engine configuration
	engineConfig := engine.EngineConfig{}
	engineInstance, err := engine.Init(engineConfig)
	if err != nil {
		return "", fmt.Errorf("error initializing engine: %w", err)
	}

	// Start processing items
	cmd.Channels.WaitGroup.Add(1)
	go cmd.ProcessItems(engineInstance, "")

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
			items <- item
		}(scanItem)
	}
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
