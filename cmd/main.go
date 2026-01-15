package cmd

import (
	"context"
	"fmt"

	"github.com/checkmarx/2ms/v4/engine"
	"github.com/checkmarx/2ms/v4/lib/config"
	"github.com/checkmarx/2ms/v4/plugins"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var Version = "0.0.0"

const (
	outputFormatRegexpPattern = `^(ya?ml|json|sarif)$`
	configFileFlag            = "config"

	logLevelFlagName                  = "log-level"
	reportPathFlagName                = "report-path"
	stdoutFormatFlagName              = "stdout-format"
	customRegexRuleFlagName           = "regex"
	ruleFlagName                      = "rule"
	ignoreRuleFlagName                = "ignore-rule"
	ignoreFlagName                    = "ignore-result"
	allowedValuesFlagName             = "allowed-values"
	specialRulesFlagName              = "add-special-rule"
	ignoreOnExitFlagName              = "ignore-on-exit"
	maxTargetMegabytesFlagName        = "max-target-megabytes"
	maxFindingsFlagName               = "max-findings"
	maxRuleMatchesPerFragmentFlagName = "max-rule-matches-per-fragment"
	maxSecretSizeFlagName             = "max-secret-size"
	validate                          = "validate"
	customRulesFileFlagName           = "custom-rules-path"
)

var (
	logLevelVar        string
	reportPathVar      []string
	stdoutFormatVar    string
	customRegexRuleVar []string
	ignoreOnExitVar    = ignoreOnExitNone
	engineConfigVar    engine.EngineConfig
	validateVar        bool
	customRulesPathVar string
)

const envPrefix = "2MS"

var configFilePath string
var vConfig = viper.New()

var allPlugins = []plugins.IPlugin{
	plugins.NewConfluencePlugin(),
	&plugins.DiscordPlugin{},
	&plugins.FileSystemPlugin{},
	&plugins.SlackPlugin{},
	&plugins.PaligoPlugin{},
	plugins.NewGitPlugin(),
}

func Execute() (int, error) {
	vConfig.SetEnvPrefix(envPrefix)
	vConfig.AutomaticEnv()

	rootCmd := &cobra.Command{
		Use:     "2ms",
		Short:   "2ms Secrets Detection",
		Long:    "2ms Secrets Detection: A tool to detect secrets in public websites and communication services.",
		Version: Version,
	}

	setupFlags(rootCmd)

	rootCmd.AddCommand(engine.GetRulesCommand(&engineConfigVar))

	// Override detector worker pool size from environment if set
	if detectorWorkerPoolSize := vConfig.GetInt("TWOMS_DETECTOR_WORKERPOOL_SIZE"); detectorWorkerPoolSize != 0 {
		engineConfigVar.DetectorWorkerPoolSize = detectorWorkerPoolSize
		log.Info().Msgf("TWOMS_DETECTOR_WORKERPOOL_SIZE is set to %d", detectorWorkerPoolSize)
	}

	group := "Scan Commands"
	rootCmd.AddGroup(&cobra.Group{Title: group, ID: group})

	channels := plugins.NewChannels()
	var engineInstance engine.IEngine

	// Process flags and initialize engine with complete configuration
	cobra.OnInitialize(func() {
		if err := processFlags(rootCmd); err != nil {
			cobra.CheckErr(err)
		}

		if len(engineConfigVar.CustomRegexPatterns) > 0 {
			log.Info().Msgf("Custom regex patterns configured: %v", engineConfigVar.CustomRegexPatterns)
		}
		if len(engineConfigVar.IgnoreList) > 0 {
			log.Info().Msgf("Ignore rules configured: %v", engineConfigVar.IgnoreList)
		}

		var err error
		engineInstance, err = engine.Init(&engineConfigVar, engine.WithPluginChannels(channels))
		if err != nil {
			cobra.CheckErr(fmt.Errorf("failed to initialize engine: %w", err))
		}
	})

	// Set up plugins
	for _, plugin := range allPlugins {
		subCommand, err := plugin.DefineCommand(channels.GetItemsCh(), channels.GetErrorsCh())
		if err != nil {
			return 0, fmt.Errorf("error while defining command for plugin %s: %s", plugin.GetName(), err.Error())
		}
		subCommand.GroupID = group

		pluginPreRun := subCommand.PreRunE
		// Capture plugin name for closure
		pluginName := plugin.GetName()
		subCommand.PreRunE = func(cmd *cobra.Command, args []string) error {
			// run plugin's own PreRunE (if any)
			if pluginPreRun != nil {
				if err := pluginPreRun(cmd, args); err != nil {
					return err
				}
			}
			// run engine-level PreRunE
			return preRun(pluginName, engineInstance, cmd, args)
		}
		subCommand.PostRunE = func(cmd *cobra.Command, args []string) error {
			return postRun(engineInstance)
		}
		rootCmd.AddCommand(subCommand)
	}

	listenForErrors(channels.GetErrorsCh())

	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		return 0, err
	}

	if engineInstance != nil {
		return engineInstance.GetReport().GetTotalSecretsFound(), nil
	}

	return 0, nil
}

func preRun(pluginName string, engineInstance engine.IEngine, _ *cobra.Command, _ []string) error {
	if engineInstance == nil {
		return fmt.Errorf("engine instance not initialized")
	}

	if err := validateFormat(stdoutFormatVar, reportPathVar); err != nil {
		return err
	}

	engineInstance.Scan(pluginName)

	return nil
}

func postRun(engineInstance engine.IEngine) error {
	if engineInstance == nil {
		return fmt.Errorf("engine instance not initialized")
	}

	engineInstance.Wait()

	cfg := config.LoadConfig("2ms", Version)
	report := engineInstance.GetReport()

	if report.GetTotalItemsScanned() > 0 {
		if zerolog.GlobalLevel() != zerolog.Disabled {
			if err := report.ShowReport(stdoutFormatVar, cfg); err != nil {
				return err
			}
		}

		if len(reportPathVar) > 0 {
			err := report.WriteFile(reportPathVar, cfg)
			if err != nil {
				return fmt.Errorf("failed to create report file with error: %s", err)
			}
		}
	} else {
		log.Info().Msg("Scan completed with empty content")
	}

	if err := engineInstance.Shutdown(); err != nil {
		return err
	}

	return nil
}
