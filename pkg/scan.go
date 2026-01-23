package scanner

import (
	"errors"
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/v5/internal/resources"
	"github.com/checkmarx/2ms/v5/plugins"
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/conc"

	"github.com/checkmarx/2ms/v5/lib/reporting"

	"github.com/checkmarx/2ms/v5/engine"
)

type scanner struct {
	engineInstance engine.IEngine
	scanConfig     resources.ScanConfig
	mu             sync.RWMutex
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

func (s *scanner) Reset(scanConfig *resources.ScanConfig, opts ...engine.EngineOption) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	engineInstance, err := engine.Init(&engine.EngineConfig{
		IgnoredIds:                scanConfig.IgnoreResultIds,
		SelectedList:              scanConfig.SelectRules,
		CustomRules:               scanConfig.CustomRules,
		IgnoreList:                scanConfig.IgnoreRules,
		MaxFindings:               scanConfig.MaxFindings,
		MaxRuleMatchesPerFragment: scanConfig.MaxRuleMatchesPerFragment,
		MaxSecretSize:             scanConfig.MaxSecretSize,
		ScanConfig:                *scanConfig,
	}, opts...)
	if err != nil {
		return fmt.Errorf("error initializing engine: %w", err)
	}

	s.engineInstance = engineInstance
	s.scanConfig = *scanConfig

	return nil
}

func (s *scanner) Scan(scanItems []ScanItem, scanConfig *resources.ScanConfig, opts ...engine.EngineOption) (reporting.IReport, error) {
	var wg conc.WaitGroup
	err := s.Reset(scanConfig, opts...)
	if err != nil {
		return nil, fmt.Errorf("error resetting engine: %w", err)
	}

	if len(scanItems) == 0 {
		return s.engineInstance.GetReport(), nil
	}

	bufferedErrors := make(chan error, len(scanItems)+1)

	go func() {
		defer close(bufferedErrors)

		for err := range s.engineInstance.GetErrorsCh() {
			bufferedErrors <- err
		}
	}()

	s.engineInstance.Scan(s.scanConfig.PluginName)

	wg.Go(func() {
		defer close(s.engineInstance.GetPluginChannels().GetItemsCh())

		for _, item := range scanItems {
			s.engineInstance.GetPluginChannels().GetItemsCh() <- item
		}
	})

	wg.Go(func() {
		s.engineInstance.Wait()
	})

	wg.Wait()

	close(s.engineInstance.GetErrorsCh())

	var errs []error
	for err = range bufferedErrors {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return reporting.New().(*reporting.Report), fmt.Errorf("error(s) processing scan items:\n%w", errors.Join(errs...))
	}

	return s.engineInstance.GetReport(), nil
}

func (s *scanner) ScanDynamic(
	itemsIn <-chan ScanItem,
	scanConfig *resources.ScanConfig,
	opts ...engine.EngineOption,
) (reporting.IReport, error) {
	var wg conc.WaitGroup
	err := s.Reset(scanConfig, opts...)
	if err != nil {
		return reporting.New().(*reporting.Report), fmt.Errorf("error resetting engine: %w", err)
	}

	s.engineInstance.Scan(s.scanConfig.PluginName)

	channels := s.engineInstance.GetPluginChannels()
	wg.Go(func() {
		defer close(channels.GetItemsCh())

		for item := range itemsIn {
			channels.GetItemsCh() <- item
		}

		log.Info().Msg("scan dynamic finished sending items to engine")
	})

	bufferedErrors := make(chan error, 2)

	go func() {
		defer close(bufferedErrors)

		for err := range s.engineInstance.GetErrorsCh() {
			bufferedErrors <- err
		}
	}()

	wg.Go(func() {
		s.engineInstance.Wait()
	})

	wg.Wait()

	close(s.engineInstance.GetErrorsCh())

	var errs []error
	for err = range bufferedErrors {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return reporting.New().(*reporting.Report), fmt.Errorf("error(s) processing scan items:\n%w", errors.Join(errs...))
	}

	return s.engineInstance.GetReport(), nil
}
