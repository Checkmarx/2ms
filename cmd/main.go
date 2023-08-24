package cmd

import (
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/checkmarx/2ms/config"
	"github.com/checkmarx/2ms/lib"

	"sync"

	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/reporting"
	"github.com/checkmarx/2ms/secrets"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var Version = "0.0.0"

const (
	timeSleepInterval         = 50
	outputFormatRegexpPattern = `^(ya?ml|json|sarif)$`
	configFileFlag            = "config"

	logLevelFlagName        = "log-level"
	reportPathFlagName      = "report-path"
	stdoutFormatFlagName    = "stdout-format"
	customRegexRuleFlagName = "regex"
	includeRuleFlagName     = "include-rule"
	excludeRuleFlagName     = "exclude-rule"
	ignoreFlagName          = "ignore-result"
	ignoreOnExitFlagName    = "ignore-on-exit"
)

var (
	logLevelVar        string
	reportPathVar      []string
	stdoutFormatVar    string
	customRegexRuleVar []string
	includeRuleVar     []string
	excludeRuleVar     []string
	ignoreVar          []string
	ignoreOnExitVar    string
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
	Items:     make(chan plugins.Item),
	Errors:    make(chan error),
	WaitGroup: &sync.WaitGroup{},
}

var report = reporting.Init()
var secretsChan = make(chan reporting.Secret)
var errorChan = make(chan error, 1)

func initialize() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	configFilePath, err := rootCmd.Flags().GetString(configFileFlag)
	if err != nil {
		cobra.CheckErr(err)
	}
	cobra.CheckErr(lib.LoadConfig(vConfig, configFilePath))
	cobra.CheckErr(lib.BindFlags(rootCmd, vConfig, envPrefix))

	switch strings.ToLower(logLevelVar) {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "err", "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func Execute() error {
	vConfig.SetEnvPrefix(envPrefix)
	vConfig.AutomaticEnv()

	cobra.OnInitialize(initialize)
	rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "config file path")
	cobra.CheckErr(rootCmd.MarkPersistentFlagFilename(configFileFlag, "yaml", "yml", "json"))
	rootCmd.PersistentFlags().StringVar(&logLevelVar, logLevelFlagName, "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().StringSliceVar(&reportPathVar, reportPathFlagName, []string{}, "path to generate report files. The output format will be determined by the file extension (.json, .yaml, .sarif)")
	rootCmd.PersistentFlags().StringVar(&stdoutFormatVar, stdoutFormatFlagName, "yaml", "stdout output format, available formats are: json, yaml, sarif")
	rootCmd.PersistentFlags().StringArrayVar(&customRegexRuleVar, customRegexRuleFlagName, []string{}, "custom regexes to apply to the scan, must be valid Go regex")
	rootCmd.PersistentFlags().StringSliceVar(&includeRuleVar, includeRuleFlagName, []string{}, "include rules by name or tag to apply to the scan (adds to list, starts from empty)")
	rootCmd.PersistentFlags().StringSliceVar(&excludeRuleVar, excludeRuleFlagName, []string{}, "exclude rules by name or tag to apply to the scan (removes from list, starts from all)")
	rootCmd.MarkFlagsMutuallyExclusive(includeRuleFlagName, excludeRuleFlagName)
	rootCmd.PersistentFlags().StringSliceVar(&ignoreVar, ignoreFlagName, []string{}, "ignore specific result by id")
	rootCmd.PersistentFlags().StringVar(&ignoreOnExitVar, ignoreOnExitFlagName, "none", "defines which kind of non-zero exits code should be ignored\naccepts: all, results, errors, none\nexample: if 'results' is set, only engine errors will make 2ms exit code different from 0")

	rootCmd.AddCommand(secrets.RulesCommand)

	group := "Commands"
	rootCmd.AddGroup(&cobra.Group{Title: group, ID: group})

	for _, plugin := range allPlugins {
		subCommand, err := plugin.DefineCommand(channels.Items, channels.Errors)
		if err != nil {
			return fmt.Errorf("error while defining command for plugin %s: %s", plugin.GetName(), err.Error())
		}
		subCommand.GroupID = group
		subCommand.PreRunE = preRun
		subCommand.PostRunE = postRun
		rootCmd.AddCommand(subCommand)
	}

	if err := rootCmd.Execute(); err != nil {
		return err
	}

	if report.TotalSecretsFound > 0 && ShowError("errors") {
		return fmt.Errorf("")
	}

	return nil
}

func validateFormat(stdout string, reportPath []string) error {
	r := regexp.MustCompile(outputFormatRegexpPattern)
	if !(r.MatchString(stdout)) {
		return fmt.Errorf(`invalid output format: %s, available formats are: json, yaml and sarif`, stdout)
	}

	for _, path := range reportPath {
		fileExtension := filepath.Ext(path)
		format := strings.TrimPrefix(fileExtension, ".")
		if !(r.MatchString(format)) {
			return fmt.Errorf(`invalid report extension: %s, available extensions are: json, yaml and sarif`, format)
		}
	}

	return nil
}

func preRun(cmd *cobra.Command, args []string) error {
	if err := validateFormat(stdoutFormatVar, reportPathVar); err != nil {
		return err
	}

	secrets, err := secrets.Init(includeRuleVar, excludeRuleVar)
	if err != nil {
		return err
	}

	if err := secrets.AddRegexRules(customRegexRuleVar); err != nil {
		return err
	}

	if err := InitShouldIgnoreArg(ignoreOnExitVar); err != nil {
		return err
	}

	channels.WaitGroup.Add(1)
	go func() {
		defer channels.WaitGroup.Done()

		wgItems := &sync.WaitGroup{}
		for item := range channels.Items {
			report.TotalItemsScanned++
			wgItems.Add(1)
			go secrets.Detect(item, secretsChan, wgItems, ignoreVar)
		}
		wgItems.Wait()
		close(secretsChan)
	}()

	channels.WaitGroup.Add(1)
	go func() {
		defer channels.WaitGroup.Done()
		for secret := range secretsChan {
			report.TotalSecretsFound++
			report.Results[secret.ID] = append(report.Results[secret.ID], secret)
		}
	}()

	go func() {
		for err := range channels.Errors {
			log.Fatal().Msg(err.Error())
		}
	}()

	return nil
}

func postRun(cmd *cobra.Command, args []string) error {
	channels.WaitGroup.Wait()

	cfg := config.LoadConfig("2ms", Version)

	// -------------------------------------
	// Show Report
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
		fmt.Println("Scan completed with empty content")
	}

	return nil
}

// InitShouldIgnoreArg initializes what kind of errors should be used on exit codes
func InitShouldIgnoreArg(arg string) error {
	validArgs := []string{"none", "all", "results", "errors"}
	for _, validArg := range validArgs {
		if strings.EqualFold(validArg, arg) {
			ignoreOnExitVar = strings.ToLower(arg)
			return nil
		}
	}
	return fmt.Errorf("unknown argument for --ignore-on-exit: %s\nvalid arguments:\n  %s", arg, strings.Join(validArgs, "\n  "))
}

// ShowError returns true if should show error, otherwise returns false
func ShowError(kind string) bool {
	return strings.EqualFold(ignoreOnExitVar, "none") || (!strings.EqualFold(ignoreOnExitVar, "all") && !strings.EqualFold(ignoreOnExitVar, kind))
}
