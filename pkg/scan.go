package scanner

import (
	"errors"
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/v3/lib/secrets"
	"github.com/checkmarx/2ms/v3/plugins"

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

func resetCmdGlobals() {
	cmd.Channels = plugins.Channels{
		Items:     make(chan plugins.ISourceItem),
		Errors:    make(chan error),
		WaitGroup: &sync.WaitGroup{},
	}

	cmd.Report = reporting.Init()

	cmd.SecretsChan = make(chan *secrets.Secret)
	cmd.SecretsExtrasChan = make(chan *secrets.Secret)
	cmd.ValidationChan = make(chan *secrets.Secret)
	cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
}

func (s *scanner) Scan(scanItems []ScanItem, scanConfig ScanConfig) (*reporting.Report, error) {
	resetCmdGlobals()

	bufferedErrors := make(chan error, len(scanItems)+1)
	wg := &sync.WaitGroup{}

	go func() {
		for err := range cmd.Channels.Errors {
			if err != nil {
				bufferedErrors <- err
			}
		}
		close(bufferedErrors)
	}()

	engineConfig := engine.EngineConfig{
		IgnoredIds: scanConfig.IgnoreResultIds,
		IgnoreList: scanConfig.IgnoreRules,
	}
	engineInstance, err := engine.Init(engineConfig)
	if err != nil {
		return &reporting.Report{}, fmt.Errorf("error initializing engine: %w", err)
	}

	startPipeline(engineInstance, scanConfig.WithValidation)

	for _, item := range scanItems {
		wg.Add(1)
		go func(si ScanItem) {
			defer wg.Done()
			cmd.Channels.Items <- si
		}(item)
	}
	wg.Wait()
	close(cmd.Channels.Items)

	cmd.Channels.WaitGroup.Wait()
	close(cmd.Channels.Errors)

	var errs []error
	for err = range bufferedErrors {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return &reporting.Report{}, fmt.Errorf("error(s) processing scan items:\n%w", errors.Join(errs...))
	}

	engineInstance.Shutdown()

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
	resetCmdGlobals()

	engineConfig := engine.EngineConfig{
		IgnoredIds: scanConfig.IgnoreResultIds,
		IgnoreList: scanConfig.IgnoreRules,
	}
	engineInstance, err := engine.Init(engineConfig)
	if err != nil {
		return &reporting.Report{}, fmt.Errorf("error initializing engine: %w", err)
	}

	startPipeline(engineInstance, false)

	go func() {
		for item := range itemsIn {
			cmd.Channels.Items <- item
		}
		close(cmd.Channels.Items)
	}()

	cmd.Channels.WaitGroup.Wait()
	close(cmd.Channels.Errors)

	for err := range cmd.Channels.Errors {
		if err != nil {
			return &reporting.Report{}, fmt.Errorf("error processing scan items: %w", err)
		}
	}

	return cmd.Report, nil
}
