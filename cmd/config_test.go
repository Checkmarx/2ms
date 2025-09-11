package cmd

import (
	"os"
	"path/filepath"
	"testing"

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

				initialize(rootCmd)

				assert.Equal(t, tc.expectedLevel, zerolog.GlobalLevel())
				assert.Equal(t, tc.expectedLevel, log.Logger.GetLevel())
			}

			err := rootCmd.Execute()
			assert.NoError(t, err, "Error executing command")
		})
	}
}

func TestConfigGile(t *testing.T) {
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
