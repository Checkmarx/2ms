package cmd

import (
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
	timeSleepInterval         = 50
	outputFormatRegexpPattern = `^(ya?ml|json|sarif)$`
	configFileFlag            = "config"

	logLevelFlagName           = "log-level"
	reportPathFlagName         = "report-path"
	stdoutFormatFlagName       = "stdout-format"
	customRegexRuleFlagName    = "regex"
	ruleFlagName               = "rule"
	ignoreRuleFlagName         = "ignore-rule"
	ignoreFlagName             = "ignore-result"
	allowedValuesFlagName      = "allowed-values"
	specialRulesFlagName       = "add-special-rule"
	ignoreOnExitFlagName       = "ignore-on-exit"
	maxTargetMegabytesFlagName = "max-target-megabytes"
	validate                   = "validate"
)

var (
	logLevelVar        string
	reportPathVar      []string
	stdoutFormatVar    string
	customRegexRuleVar []string
	ignoreOnExitVar    = ignoreOnExitNone
	engineConfigVar    engine.EngineConfig
	validateVar        bool
)

var rootCmd = &cobra.Command{
	Use:     "2ms",
	Short:   "2ms Secrets Detection",
	Long:    "2ms Secrets Detection: A tool to detect secrets in public websites and communication services.",
	Version: Version,
}

const envPrefix = "2MS"

var configFilePath string
var vConfig = viper.New()

var allPlugins = []plugins.IPlugin{
	&plugins.ConfluencePlugin{},
	&plugins.DiscordPlugin{},
	&plugins.FileSystemPlugin{},
	&plugins.SlackPlugin{},
	&plugins.PaligoPlugin{},
	plugins.NewGitPlugin(),
}

func Execute() (int, error) {
	vConfig.SetEnvPrefix(envPrefix)
	vConfig.AutomaticEnv()

	cobra.OnInitialize(initialize)
	rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "config file path")
	cobra.CheckErr(rootCmd.MarkPersistentFlagFilename(configFileFlag, "yaml", "yml", "json"))
	rootCmd.PersistentFlags().StringVar(&logLevelVar, logLevelFlagName, "info", "log level (trace, debug, info, warn, error, fatal, none)")
	rootCmd.PersistentFlags().
		StringSliceVar(&reportPathVar, reportPathFlagName, []string{},
			"path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif)")
	rootCmd.PersistentFlags().
		StringVar(&stdoutFormatVar, stdoutFormatFlagName, "yaml", "stdout output format, available formats are: json, yaml, sarif")
	rootCmd.PersistentFlags().
		StringArrayVar(&customRegexRuleVar, customRegexRuleFlagName, []string{}, "custom regexes to apply to the scan, must be valid Go regex")
	rootCmd.PersistentFlags().
		StringSliceVar(&engineConfigVar.SelectedList, ruleFlagName, []string{}, "select rules by name or tag to apply to this scan")
	rootCmd.PersistentFlags().StringSliceVar(&engineConfigVar.IgnoreList, ignoreRuleFlagName, []string{}, "ignore rules by name or tag")
	rootCmd.PersistentFlags().StringSliceVar(&engineConfigVar.IgnoredIds, ignoreFlagName, []string{}, "ignore specific result by id")
	rootCmd.PersistentFlags().
		StringSliceVar(&engineConfigVar.AllowedValues, allowedValuesFlagName, []string{}, "allowed secrets values to ignore")
	rootCmd.PersistentFlags().
		StringSliceVar(&engineConfigVar.SpecialList, specialRulesFlagName, []string{},
			"special (non-default) rules to apply.\nThis list is not affected by the --rule and --ignore-rule flags.")
	rootCmd.PersistentFlags().
		Var(&ignoreOnExitVar, ignoreOnExitFlagName,
			"defines which kind of non-zero exits code should be ignored\naccepts: all, results, errors, none\n"+
				"example: if 'results' is set, only engine errors will make 2ms exit code different from 0")
	rootCmd.PersistentFlags().
		IntVar(&engineConfigVar.MaxTargetMegabytes, maxTargetMegabytesFlagName, 0,
			"files larger than this will be skipped.\nOmit or set to 0 to disable this check.")
	rootCmd.PersistentFlags().
		BoolVar(&validateVar, validate, false, "trigger additional validation to check if discovered secrets are valid or invalid")

	rootCmd.AddCommand(engine.GetRulesCommand(&engineConfigVar))
	// TODO: This is temporary, remove this after the refactor
	if detectorWorkerPoolSize := vConfig.GetInt("TWOMS_DETECTOR_WORKERPOOL_SIZE"); detectorWorkerPoolSize != 0 {
		engineConfigVar.DetectorWorkerPoolSize = detectorWorkerPoolSize
		log.Info().Msgf("TWOMS_DETECTOR_WORKERPOOL_SIZE is set to %d", detectorWorkerPoolSize)
	}

	group := "Scan Commands"
	rootCmd.AddGroup(&cobra.Group{Title: group, ID: group})

	engineInstance, err := engine.Init(&engineConfigVar)
	if err != nil {
		return 0, err
	}

	channels := engineInstance.GetPluginChannels()

	for _, plugin := range allPlugins {
		subCommand, err := plugin.DefineCommand(channels.GetItemsCh(), channels.GetErrorsCh())
		if err != nil {
			return 0, fmt.Errorf("error while defining command for plugin %s: %s", plugin.GetName(), err.Error())
		}
		subCommand.GroupID = group
		subCommand.PreRunE = func(cmd *cobra.Command, args []string) error {
			return preRun(plugin.GetName(), cmd, args)
		}
		subCommand.PostRunE = postRun
		rootCmd.AddCommand(subCommand)
	}

	listenForErrors(channels.GetErrorsCh())

	if err := rootCmd.Execute(); err != nil {
		return 0, err
	}

	return engineInstance.GetReport().GetTotalSecretsFound(), nil
}

func preRun(pluginName string, _ *cobra.Command, _ []string) error {
	if err := validateFormat(stdoutFormatVar, reportPathVar); err != nil {
		return err
	}

	var engineInstance engine.IEngine
	var err, initErr error
	engineInstance, err = engine.GetInstance()
	if engineInstance == nil {
		engineInstance, initErr = engine.Init(&engineConfigVar)
		if initErr != nil {
			return fmt.Errorf("error while getting engine instance: %w %w", initErr, err)
		}
	}

	if err := engineInstance.AddRegexRules(customRegexRuleVar); err != nil {
		return err
	}

	// Start processing pipeline with improved goroutine management
	startProcessingPipeline(engineInstance, pluginName, validateVar)

	return nil
}

// ProcessingTask represents a processing task with metadata
type ProcessingTask struct {
	Name string
	Fn   func()
}

// startProcessingPipeline launches all processing goroutines in a more organized way
func startProcessingPipeline(engineInstance engine.IEngine, pluginName string, validateVar bool) {
	// Define all the processing tasks with descriptive names
	tasks := []ProcessingTask{
		{"ProcessItems", func() { engineInstance.ProcessItems(pluginName) }},
		{"ProcessSecrets", func() { engineInstance.ProcessSecrets(validateVar) }},
		{"ProcessSecretsExtras", func() { engineInstance.ProcessSecretsExtras() }},
	}

	// Add validation-specific processing task
	if validateVar {
		tasks = append(tasks, ProcessingTask{
			"ProcessValidationAndScore",
			func() { engineInstance.ProcessValidationAndScoreWithValidation() },
		})
	} else {
		tasks = append(tasks, ProcessingTask{
			"ProcessScore",
			func() { engineInstance.ProcessScoreWithoutValidation() },
		})
	}

	// Launch all goroutines with better error handling potential
	launchTasks(engineInstance, tasks)
}

// launchTasks starts all tasks as goroutines with proper WaitGroup management
func launchTasks(engineInstance engine.IEngine, tasks []ProcessingTask) {
	for _, task := range tasks {
		engineInstance.AddWaitGroup(1)
		go func(t ProcessingTask) {
			// This could be extended to add logging, metrics, or error handling
			// log.Debug().Str("task", t.Name).Msg("Starting processing task")
			t.Fn()
			// log.Debug().Str("task", t.Name).Msg("Completed processing task")
		}(task)
	}
}

func postRun(cmd *cobra.Command, args []string) error {
	engineInstance, err := engine.GetInstance()
	if err != nil {
		return fmt.Errorf("error while getting engine instance: %s", err.Error())
	}
	channels := engineInstance.GetPluginChannels()
	channels.GetWaitGroup().Wait()

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
