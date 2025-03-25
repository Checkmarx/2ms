package cmd

import (
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/lib/config"
	"github.com/checkmarx/2ms/lib/reporting"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
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
	&plugins.GitPlugin{},
}

var channels = plugins.Channels{
	Items:     make(chan plugins.ISourceItem),
	Errors:    make(chan error),
	WaitGroup: &sync.WaitGroup{},
}

var report = reporting.Init()
var secretsChan = make(chan *secrets.Secret)
var secretsExtrasChan = make(chan *secrets.Secret)
var validationChan = make(chan *secrets.Secret)
var cvssScoreWithoutValidationChan = make(chan *secrets.Secret)

func Execute() (int, error) {
	vConfig.SetEnvPrefix(envPrefix)
	vConfig.AutomaticEnv()

	cobra.OnInitialize(initialize)
	rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "config file path")
	cobra.CheckErr(rootCmd.MarkPersistentFlagFilename(configFileFlag, "yaml", "yml", "json"))
	rootCmd.PersistentFlags().StringVar(&logLevelVar, logLevelFlagName, "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().StringSliceVar(&reportPathVar, reportPathFlagName, []string{}, "path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif)")
	rootCmd.PersistentFlags().StringVar(&stdoutFormatVar, stdoutFormatFlagName, "yaml", "stdout output format, available formats are: json, yaml, sarif")
	rootCmd.PersistentFlags().StringArrayVar(&customRegexRuleVar, customRegexRuleFlagName, []string{}, "custom regexes to apply to the scan, must be valid Go regex")
	rootCmd.PersistentFlags().StringSliceVar(&engineConfigVar.SelectedList, ruleFlagName, []string{}, "select rules by name or tag to apply to this scan")
	rootCmd.PersistentFlags().StringSliceVar(&engineConfigVar.IgnoreList, ignoreRuleFlagName, []string{}, "ignore rules by name or tag")
	rootCmd.PersistentFlags().StringSliceVar(&engineConfigVar.IgnoredIds, ignoreFlagName, []string{}, "ignore specific result by id")
	rootCmd.PersistentFlags().StringSliceVar(&engineConfigVar.AllowedValues, allowedValuesFlagName, []string{}, "allowed secrets values to ignore")
	rootCmd.PersistentFlags().StringSliceVar(&engineConfigVar.SpecialList, specialRulesFlagName, []string{}, "special (non-default) rules to apply.\nThis list is not affected by the --rule and --ignore-rule flags.")
	rootCmd.PersistentFlags().Var(&ignoreOnExitVar, ignoreOnExitFlagName, "defines which kind of non-zero exits code should be ignored\naccepts: all, results, errors, none\nexample: if 'results' is set, only engine errors will make 2ms exit code different from 0")
	rootCmd.PersistentFlags().IntVar(&engineConfigVar.MaxTargetMegabytes, maxTargetMegabytesFlagName, 0, "files larger than this will be skipped.\nOmit or set to 0 to disable this check.")
	rootCmd.PersistentFlags().BoolVar(&validateVar, validate, false, "trigger additional validation to check if discovered secrets are valid or invalid")

	rootCmd.AddCommand(engine.GetRulesCommand(&engineConfigVar))

	group := "Scan Commands"
	rootCmd.AddGroup(&cobra.Group{Title: group, ID: group})

	for _, plugin := range allPlugins {
		subCommand, err := plugin.DefineCommand(channels.Items, channels.Errors)
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

	listenForErrors(channels.Errors)

	if err := rootCmd.Execute(); err != nil {
		return 0, err
	}

	return report.TotalSecretsFound, nil
}

func preRun(pluginName string, cmd *cobra.Command, args []string) error {
	if err := validateFormat(stdoutFormatVar, reportPathVar); err != nil {
		return err
	}

	engine, err := engine.Init(engineConfigVar)
	if err != nil {
		return err
	}

	if err := engine.AddRegexRules(customRegexRuleVar); err != nil {
		return err
	}

	channels.WaitGroup.Add(1)
	go processItems(engine, pluginName)

	channels.WaitGroup.Add(1)
	go processSecrets()

	channels.WaitGroup.Add(1)
	go processSecretsExtras()

	if validateVar {
		channels.WaitGroup.Add(1)
		go processValidationAndScoreWithValidation(engine)
	} else {
		channels.WaitGroup.Add(1)
		go processScoreWithoutValidation(engine)
	}

	return nil
}

func postRun(cmd *cobra.Command, args []string) error {
	channels.WaitGroup.Wait()

	cfg := config.LoadConfig("2ms", Version)

	if report.TotalItemsScanned > 0 {
		if err := report.ShowReport(stdoutFormatVar, cfg); err != nil {
			return err
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

	return nil
}
