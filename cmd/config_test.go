package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestValidateFormat(t *testing.T) {
	tests := []struct {
		name            string
		stdoutFormatVar string
		reportPath      []string
		expectedErr     error
	}{
		{
			name:            "valid output format and report extension json",
			stdoutFormatVar: "json",
			reportPath:      []string{"report.json"},
			expectedErr:     nil,
		},
		{
			name:            "valid output format and report extension yaml",
			stdoutFormatVar: "yaml",
			reportPath:      []string{"report.yaml"},
			expectedErr:     nil,
		},
		{
			name:            "valid output format and report extension sarif",
			stdoutFormatVar: "sarif",
			reportPath:      []string{"report.sarif"},
			expectedErr:     nil,
		},
		{
			name:            "invalid output format",
			stdoutFormatVar: "invalid",
			reportPath:      []string{"report.json"},
			expectedErr:     errInvalidOutputFormat,
		},
		{
			name:            "invalid report extension",
			stdoutFormatVar: "json",
			reportPath:      []string{"report.invalid"},
			expectedErr:     errInvalidReportExtension,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFormat(tt.stdoutFormatVar, tt.reportPath)
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestInitializeLogLevels(t *testing.T) {
	testCases := []struct {
		name          string
		logLevelInput string
		expectedLevel zerolog.Level
	}{
		{"Trace Level", "trace", zerolog.TraceLevel},
		{"Debug Level", "debug", zerolog.DebugLevel},
		{"Info Level", "info", zerolog.InfoLevel},
		{"Warn Level", "warn", zerolog.WarnLevel},
		{"Error Level with 'error'", "error", zerolog.ErrorLevel},
		{"Error Level with 'err'", "err", zerolog.ErrorLevel},
		{"Fatal Level", "fatal", zerolog.FatalLevel},
		{"Invalid Level Defaults to Info", "invalid", zerolog.InfoLevel},
		{"Empty Level Defaults to Info", "", zerolog.InfoLevel},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rootCmd := &cobra.Command{
				Use: "test",
			}
			rootCmd.Run = func(cmd *cobra.Command, args []string) {
				cmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "")
				cmd.PersistentFlags().StringVar(&logLevelVar, logLevelFlagName, "", "")

				err := cmd.PersistentFlags().Set(configFileFlag, "")
				assert.NoError(t, err)

				err = cmd.PersistentFlags().Set(logLevelFlagName, tc.logLevelInput)
				assert.NoError(t, err)

				processFlags(rootCmd)

				assert.Equal(t, tc.expectedLevel, zerolog.GlobalLevel())
				assert.Equal(t, tc.expectedLevel, log.Logger.GetLevel())
			}

			err := rootCmd.Execute()
			assert.NoError(t, err, "Error executing command")
		})
	}
}

func TestProcessFlags(t *testing.T) {
	t.Run("CustomRegexPatternMapping", func(t *testing.T) {
		// Reset global variables
		customRegexRuleVar = []string{}
		engineConfigVar.CustomRegexPatterns = []string{}

		// Set test values
		customRegexRuleVar = []string{"CUSTOM_[A-Z]+", "SECRET_[0-9]+"}

		// Process flags
		rootCmd := &cobra.Command{Use: "test"}
		rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "")
		processFlags(rootCmd)

		// Verify mapping
		assert.Equal(t, customRegexRuleVar, engineConfigVar.CustomRegexPatterns, "customRegexRuleVar should be mapped to engineConfigVar.CustomRegexPatterns")
	})

	t.Run("ValidateVarMapping", func(t *testing.T) {
		// Reset global variables
		validateVar = false
		engineConfigVar.ScanConfig.WithValidation = false

		// Set test value
		validateVar = true

		// Process flags
		rootCmd := &cobra.Command{Use: "test"}
		rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "")
		processFlags(rootCmd)

		// Verify mapping
		assert.Equal(t, validateVar, engineConfigVar.ScanConfig.WithValidation, "validateVar should be mapped to engineConfigVar.ScanConfig.WithValidation")
	})

	t.Run("IgnoreListProcessing", func(t *testing.T) {
		// Reset global variables
		engineConfigVar.IgnoreList = []string{}

		// Set test values
		engineConfigVar.IgnoreList = []string{"rule1", "rule2", "rule3"}

		// Process flags
		rootCmd := &cobra.Command{Use: "test"}
		rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "")
		processFlags(rootCmd)

		// Verify IgnoreList is preserved
		assert.Equal(t, []string{"rule1", "rule2", "rule3"}, engineConfigVar.IgnoreList, "IgnoreList should be preserved during flag processing")
	})

	t.Run("AllFlagMappings", func(t *testing.T) {
		// Reset all global variables
		customRegexRuleVar = []string{"TEST_PATTERN"}
		validateVar = true
		engineConfigVar.IgnoreList = []string{"ignored-rule"}
		engineConfigVar.MaxTargetMegabytes = 50

		// Process flags
		rootCmd := &cobra.Command{Use: "test"}
		rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "")
		processFlags(rootCmd)

		// Verify all mappings
		assert.Equal(t, customRegexRuleVar, engineConfigVar.CustomRegexPatterns, "Custom regex patterns should be mapped")
		assert.Equal(t, validateVar, engineConfigVar.ScanConfig.WithValidation, "Validation flag should be mapped")
		assert.Equal(t, []string{"ignored-rule"}, engineConfigVar.IgnoreList, "IgnoreList should be preserved")
		assert.Equal(t, 50, engineConfigVar.MaxTargetMegabytes, "MaxTargetMegabytes should be preserved")
	})

	t.Run("EmptyFlagValues", func(t *testing.T) {
		// Reset all to empty/default values
		customRegexRuleVar = []string{}
		validateVar = false
		engineConfigVar.IgnoreList = []string{}
		engineConfigVar.CustomRegexPatterns = []string{}
		engineConfigVar.ScanConfig.WithValidation = false

		// Process flags
		rootCmd := &cobra.Command{Use: "test"}
		rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "")
		processFlags(rootCmd)

		// Verify empty values are handled correctly
		assert.Empty(t, engineConfigVar.CustomRegexPatterns, "Empty custom regex patterns should remain empty")
		assert.False(t, engineConfigVar.ScanConfig.WithValidation, "Validation should be false by default")
		assert.Empty(t, engineConfigVar.IgnoreList, "Empty ignore list should remain empty")
	})
}

func TestFlagPrecedence(t *testing.T) {
	t.Run("CLIFlagsOverrideConfigFile", func(t *testing.T) {
		// Create a temp config file
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, ".2ms.yml")

		configContent := `validate: false
log-level: info
max-target-megabytes: 10`

		err := os.WriteFile(configFile, []byte(configContent), 0644)
		assert.NoError(t, err)

		// Set CLI flag values that should override config file
		validateVar = true                      // CLI sets true, config has false
		logLevelVar = "debug"                   // CLI sets debug, config has info
		engineConfigVar.MaxTargetMegabytes = 50 // CLI sets 50, config has 10

		// Process with config file
		rootCmd := &cobra.Command{Use: "test"}
		rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, configFile, "")

		processFlags(rootCmd)

		// Verify CLI values take precedence
		assert.True(t, engineConfigVar.ScanConfig.WithValidation, "CLI validate flag should override config file")
		assert.Equal(t, zerolog.DebugLevel, log.Logger.GetLevel(), "CLI log level should override config file")
	})
}

func TestConfigFile(t *testing.T) {
	t.Run("ValidConfigFile", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, ".2ms.yml")

		configContent := `log-level: debug
report-path:
 - test-report.json
stdout-format: json
max-target-megabytes: 100`

		err := os.WriteFile(configFile, []byte(configContent), 0644)
		assert.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configFile)
		err = v.ReadInConfig()
		assert.NoError(t, err)

		assert.Equal(t, "debug", v.GetString("log-level"))
		assert.Equal(t, []interface{}{"test-report.json"}, v.Get("report-path"))
		assert.Equal(t, "json", v.GetString("stdout-format"))
		assert.Equal(t, 100, v.GetInt("max-target-megabytes"))
	})

	t.Run("InvalidConfigFile", func(t *testing.T) {
		v := viper.New()
		v.SetConfigFile("/non/existent/config.yml")
		err := v.ReadInConfig()
		assert.Error(t, err)
	})

	t.Run("MalformedConfigFile", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, ".2ms.yml")

		malformedContent := `log-level: debug
report-path: [unclosed
stdout-format: json`

		err := os.WriteFile(configFile, []byte(malformedContent), 0644)
		assert.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configFile)
		err = v.ReadInConfig()
		assert.Error(t, err)
	})
}

func TestCustomRulesFlag(t *testing.T) {
	expectedRules := []*ruledefine.Rule{
		{
			RuleID:      "db18ccf1-4fbf-49f6-aec1-939a2e5464c0",
			RuleName:    "mock-rule",
			Description: "Match passwords",
			Regex:       "[A-Za-z0-9]{32}",
			Keywords:    []string{"password", "pwd"},
			Entropy:     3.5,
			Path:        "secrets/passwords.txt",
			SecretGroup: 1,
			Severity:    "High",
			OldSeverity: "Critical",
			AllowLists: []*ruledefine.AllowList{
				{
					Description:    "Ignore test files",
					MatchCondition: "OR",
					Paths:          []string{"test/.*"},
					RegexTarget:    "match",
					Regexes:        []string{"test-password", "dummy-secret"},
					StopWords:      []string{"example", "sample"},
				},
			},
			Tags:              []string{"security", "credentials"},
			Category:          "General",
			ScoreRuleType:     2,
			DisableValidation: true,
			Deprecated:        true,
		},
		{
			RuleID:            "b47a1995-6572-41bb-b01d-d215b43ab089",
			RuleName:          "mock-rule2",
			Description:       "Match API keys",
			Regex:             "[A-Za-z0-9]{40}",
			Keywords:          []string{"api", "key"},
			Entropy:           4.0,
			Path:              "config/api_keys.yaml",
			SecretGroup:       0,
			Severity:          "Medium",
			OldSeverity:       "High",
			AllowLists:        []*ruledefine.AllowList{},
			Tags:              []string{"api", "custom"},
			DisableValidation: false,
			Deprecated:        false,
		},
	}

	tests := []struct {
		name            string
		customRulesFile string
		expectedRules   []*ruledefine.Rule
		expectErrors    []error
	}{
		{
			name:            "Valid json custom rules file",
			customRulesFile: "testData/customRulesValid.json",
			expectedRules:   expectedRules,
			expectErrors:    nil,
		},
		{
			name:            "Valid yaml custom rules file",
			customRulesFile: "testData/customRulesValid.yaml",
			expectedRules:   expectedRules,
			expectErrors:    nil,
		},
		{
			name:            "Invalid custom rules file",
			customRulesFile: "testData/customRulesInvalidFormat.toml",
			expectedRules:   nil,
			expectErrors:    []error{errInvalidCustomRulesExtension},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			customRegexRuleVar = []string{}
			engineConfigVar.CustomRules = nil

			rootCmd := &cobra.Command{Use: "test"}
			rootCmd.PersistentFlags().StringVar(&configFilePath, configFileFlag, "", "")
			rootCmd.PersistentFlags().StringVar(&customRulesPathVar, customRulesFileFlagName, tt.customRulesFile, "")

			err := processFlags(rootCmd)
			for _, expectErr := range tt.expectErrors {
				assert.ErrorContains(t, err, expectErr.Error())
			}
			assert.Equal(t, tt.expectedRules, engineConfigVar.CustomRules)
		})
	}
}
