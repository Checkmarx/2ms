package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
	"github.com/checkmarx/2ms/v4/lib/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	errInvalidOutputFormat         = fmt.Errorf("invalid output format")
	errInvalidReportExtension      = fmt.Errorf("invalid report extension")
	errInvalidCustomRulesExtension = fmt.Errorf("unknown file extension, expected JSON or YAML")
)

func processFlags(rootCmd *cobra.Command) error {
	configFilePath, err := rootCmd.PersistentFlags().GetString(configFileFlag)
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	if err := utils.LoadConfig(vConfig, configFilePath); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := utils.BindFlags(rootCmd, vConfig, envPrefix); err != nil {
		return fmt.Errorf("failed to bind flags: %w", err)
	}

	// Apply all flag mappings immediately
	engineConfigVar.ScanConfig.WithValidation = validateVar
	if len(customRegexRuleVar) > 0 {
		engineConfigVar.CustomRegexPatterns = customRegexRuleVar
	}

	if customRulesPathVar != "" {
		rules, err := loadRulesFile(customRulesPathVar)
		if err != nil {
			return fmt.Errorf("failed to load custom rules file: %w", err)
		}
		engineConfigVar.CustomRules = rules
	}

	setupLogging()

	return nil
}

func setupLogging() {
	logLevel := zerolog.InfoLevel
	switch strings.ToLower(logLevelVar) {
	case "none":
		logLevel = zerolog.Disabled
	case "trace":
		logLevel = zerolog.TraceLevel
	case "debug":
		logLevel = zerolog.DebugLevel
	case "info":
		logLevel = zerolog.InfoLevel
	case "warn":
		logLevel = zerolog.WarnLevel
	case "err", "error":
		logLevel = zerolog.ErrorLevel
	case "fatal":
		logLevel = zerolog.FatalLevel
	}
	zerolog.SetGlobalLevel(logLevel)
	log.Logger = log.Logger.Level(logLevel)
}

func validateFormat(stdout string, reportPath []string) error {
	r := regexp.MustCompile(outputFormatRegexpPattern)
	if !(r.MatchString(stdout)) {
		return fmt.Errorf(`%w: %s, available formats are: json, yaml and sarif`, errInvalidOutputFormat, stdout)
	}

	for _, path := range reportPath {
		fileExtension := filepath.Ext(path)
		format := strings.TrimPrefix(fileExtension, ".")
		if !(r.MatchString(format)) {
			return fmt.Errorf(`%w: %s, available extensions are: json, yaml and sarif`, errInvalidReportExtension, format)
		}
	}

	return nil
}

func setupFlags(rootCmd *cobra.Command) {
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

	rootCmd.PersistentFlags().
		StringVar(&customRulesPathVar, customRulesFileFlagName, "", "Path to a custom rules file (JSON or YAML)."+
			" Rules should be a list of ruledefine.Rule objects. --rule, --ignore-rule still apply to custom rules")
}

func loadRulesFile(path string) ([]*ruledefine.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ext := filepath.Ext(path)
	var customRules []*ruledefine.Rule

	switch ext {
	case ".json":
		err = json.Unmarshal(data, &customRules)
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &customRules)
	default:
		return nil, errInvalidCustomRulesExtension
	}
	if err != nil {
		return nil, err
	}

	return customRules, nil
}
