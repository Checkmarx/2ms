package cmd

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
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
				cmd.Flags().StringVar(&configFilePath, configFileFlag, "", "")
				cmd.Flags().StringVar(&logLevelVar, logLevelFlagName, "", "")

				err := cmd.Flags().Set(configFileFlag, "")
				assert.NoError(t, err)

				err = cmd.Flags().Set(logLevelFlagName, tc.logLevelInput)
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
