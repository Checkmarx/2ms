package scanner

import (
	"errors"
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/v4/internal/resources"
	"github.com/checkmarx/2ms/v4/plugins"
	"github.com/rs/zerolog/log"

	"github.com/checkmarx/2ms/v4/lib/reporting"

	"github.com/checkmarx/2ms/v4/engine"
)

type scanner struct {
	engineInstance engine.IEngine
	scanConfig     resources.ScanConfig
	mu             sync.RWMutex

	once sync.Once
}

type scannerOption func(*scanner)

func WithPluginChannels(pluginChannels plugins.PluginChannels) scannerOption {
	return func(s *scanner) {
		s.engineInstance.SetPluginChannels(pluginChannels)
	}
}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Reset(scanConfig resources.ScanConfig, opts ...engine.EngineOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	engineInstance, err := engine.Init(&engine.EngineConfig{
		IgnoredIds: scanConfig.IgnoreResultIds,
		IgnoreList: scanConfig.IgnoreRules,
		ScanConfig: scanConfig,
	}, opts...)
	if err != nil {
		return fmt.Errorf("error initializing engine: %w", err)
	}

	s.engineInstance = engineInstance
	s.scanConfig = scanConfig

	return nil
}

func (s *scanner) Scan(scanItems []ScanItem, scanConfig resources.ScanConfig, opts ...engine.EngineOption) (reporting.IReport, error) {
	err := s.Reset(scanConfig, opts...)
	if err != nil {
		return nil, fmt.Errorf("error resetting engine: %w", err)
	}

	bufferedErrors := make(chan error, len(scanItems)+1)

	go func() {
		for err := range s.engineInstance.GetErrorsCh() {
			if err != nil {
				bufferedErrors <- err
			}
		}
		close(bufferedErrors)
	}()

	s.startPipeline()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, item := range scanItems {
			s.engineInstance.GetPluginChannels().GetItemsCh() <- item
		}
	}()
	wg.Wait()
	close(s.engineInstance.GetPluginChannels().GetItemsCh())

	pluginChannels := s.engineInstance.GetPluginChannels()
	pluginChannels.GetWaitGroup().Wait()
	close(pluginChannels.GetErrorsCh())

	var errs []error
	for err = range bufferedErrors {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return &reporting.Report{}, fmt.Errorf("error(s) processing scan items:\n%w", errors.Join(errs...))
	}

	if err := s.engineInstance.Shutdown(); err != nil {
		return s.engineInstance.GetReport(), fmt.Errorf("error shutting down engine: %w", err)
	}

	return s.engineInstance.GetReport(), nil
}

func (s *scanner) startPipeline() {
	pluginChannels := s.engineInstance.GetPluginChannels()
	pluginChannels.AddWaitGroup(4)

	go s.engineInstance.ProcessItems(s.scanConfig.PluginName)

	go s.engineInstance.ProcessSecrets()

	go s.engineInstance.ProcessScore()

	go s.engineInstance.ProcessSecretsExtras()
}

func (s *scanner) ScanDynamic(itemsIn <-chan ScanItem, scanConfig resources.ScanConfig, opts ...engine.EngineOption) (reporting.IReport, error) {
	err := s.Reset(scanConfig, opts...)
	if err != nil {
		return &reporting.Report{}, fmt.Errorf("error resetting engine: %w", err)
	}

	s.startPipeline()

	channels := s.engineInstance.GetPluginChannels()
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

	if err := s.engineInstance.Shutdown(); err != nil {
		return &reporting.Report{}, fmt.Errorf("error shutting down engine: %w", err)
	}

	return s.engineInstance.GetReport(), nil
}
