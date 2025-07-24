package scanner

import (
	"errors"
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/v4/plugins"
	"github.com/rs/zerolog/log"

	"github.com/checkmarx/2ms/v4/lib/reporting"

	"github.com/checkmarx/2ms/v4/cmd"
	"github.com/checkmarx/2ms/v4/engine"
)

type ScanConfig struct {
	IgnoreResultIds []string
	IgnoreRules     []string
	WithValidation  bool
	PluginName      string
}

type scanner struct {
	engineInstance engine.IEngine
	scanConfig     ScanConfig
	mu             sync.RWMutex
}

type scannerOption func(*scanner)

func WithPluginChannels(pluginChannels plugins.PluginChannels) scannerOption {
	return func(s *scanner) {
		s.engineInstance.SetPluginChannels(pluginChannels)
	}
}

func WithConfig(scanConfig ScanConfig) scannerOption {
	return func(s *scanner) {
		s.scanConfig = scanConfig
	}
}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Reset(scanConfig ScanConfig, opts ...engine.EngineOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	engineInstance, err := engine.Init(&engine.EngineConfig{
		IgnoredIds: scanConfig.IgnoreResultIds,
		IgnoreList: scanConfig.IgnoreRules,
	}, opts...)
	if err != nil {
		return fmt.Errorf("error initializing engine: %w", err)
	}

	s.engineInstance = engineInstance
	s.scanConfig = scanConfig

	return nil
}

func (s *scanner) GetEngineInstance() (engine.IEngine, error) {
	if s.engineInstance == nil {
		return nil, fmt.Errorf("engine instance is not initialized")
	}
	return s.engineInstance, nil
}

func (s *scanner) Scan(scanItems []ScanItem, scanConfig ScanConfig, opts ...engine.EngineOption) (reporting.IReport, error) {
	err := s.Reset(scanConfig, opts...)
	if err != nil {
		return nil, fmt.Errorf("error resetting engine: %w", err)
	}

	engineInstance, err := s.GetEngineInstance()
	if err != nil {
		return nil, fmt.Errorf("error getting engine instance: %w", err)
	}

	bufferedErrors := make(chan error, len(scanItems)+1)

	go func() {
		for err := range engineInstance.GetErrorsCh() {
			if err != nil {
				bufferedErrors <- err
			}
		}
		close(bufferedErrors)
	}()

	startPipeline(engineInstance, s.scanConfig.WithValidation)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, item := range scanItems {
			engineInstance.GetPluginChannels().GetItemsCh() <- item
		}
	}()
	wg.Wait()
	close(engineInstance.GetPluginChannels().GetItemsCh())

	pluginChannels := engineInstance.GetPluginChannels()
	pluginChannels.GetWaitGroup().Wait()
	close(pluginChannels.GetErrorsCh())

	var errs []error
	for err = range bufferedErrors {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return &reporting.Report{}, fmt.Errorf("error(s) processing scan items:\n%w", errors.Join(errs...))
	}

	if err := engineInstance.Shutdown(); err != nil {
		return cmd.Report, fmt.Errorf("error shutting down engine: %w", err)
	}

	return engineInstance.GetReport(), nil
}

func startPipeline(engineInstance engine.IEngine, withValidation bool) {
	pluginChannels := engineInstance.GetPluginChannels()
	pluginChannels.AddWaitGroup(4)

	go engineInstance.ProcessItems("custom")

	if withValidation {
		go engineInstance.ProcessSecretsWithValidation()
		go engineInstance.ProcessValidationAndScoreWithValidation()
	} else {
		go engineInstance.ProcessSecrets(withValidation)
		go engineInstance.ProcessScoreWithoutValidation()
	}

	go engineInstance.ProcessSecretsExtras()
}

func (s *scanner) ScanDynamic(itemsIn <-chan ScanItem, scanConfig ScanConfig, opts ...engine.EngineOption) (reporting.IReport, error) {
	err := s.Reset(scanConfig, opts...)
	if err != nil {
		return &reporting.Report{}, fmt.Errorf("error resetting engine: %w", err)
	}

	engineInstance, err := s.GetEngineInstance()
	if err != nil {
		return &reporting.Report{}, fmt.Errorf("error getting engine instance: %w", err)
	}

	startPipeline(engineInstance, false, scanConfig.PluginName)

	channels := engineInstance.GetPluginChannels()
	go func() {
		for item := range itemsIn {
			channels.GetItemsCh() <- item
		}
		close(channels.GetItemsCh())
	}()
	log.Info().Msg("scan dynamic finished sending items to engine")

	channels.GetWaitGroup().Wait()
	close(channels.GetErrorsCh())

	for err := range channels.GetErrorsCh() {
		if err != nil {
			return &reporting.Report{}, fmt.Errorf("error processing scan items: %w", err)
		}
	}

	if err := engineInstance.Shutdown(); err != nil {
		return &reporting.Report{}, fmt.Errorf("error shutting down engine: %w", err)
	}

	return engineInstance.GetReport(), nil
}
