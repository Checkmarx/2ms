package cmd

import (
	"context"
	"testing"

	"github.com/checkmarx/2ms/v4/engine"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestPreRun(t *testing.T) {
	tests := []struct {
		name               string
		stdoutFormatVar    string
		reportPath         []string
		engineConfigVar    engine.EngineConfig
		customRegexRuleVar []string
		validateVar        bool
		expectedInitErr    error
		expectedPreRunErr  error
	}{
		{
			name:               "error in validateFormat",
			stdoutFormatVar:    "invalid",
			reportPath:         []string{"report.json"},
			engineConfigVar:    engine.EngineConfig{},
			customRegexRuleVar: []string{},
			validateVar:        false,
			expectedPreRunErr:  errInvalidOutputFormat,
		},
		{
			name:            "error in engine.Init",
			stdoutFormatVar: "json",
			reportPath:      []string{"mock.json"},
			engineConfigVar: engine.EngineConfig{
				SelectedList: []string{"mockInvalid"},
			},
			customRegexRuleVar: []string{},
			validateVar:        false,
			expectedInitErr:    engine.ErrNoRulesSelected,
		},
		{
			name:               "error in engine.AddRegexRules",
			stdoutFormatVar:    "json",
			reportPath:         []string{"mock.json"},
			engineConfigVar:    engine.EngineConfig{},
			customRegexRuleVar: []string{"[a-z"},
			validateVar:        false,
			expectedPreRunErr:  engine.ErrFailedToCompileRegexRule,
		},
		{
			name:               "successfully started go routines with validateVar enabled",
			stdoutFormatVar:    "json",
			reportPath:         []string{"mock.json"},
			engineConfigVar:    engine.EngineConfig{},
			customRegexRuleVar: []string{},
			validateVar:        true,
			expectedPreRunErr:  nil,
		},
		{
			name:               "successfully started go routines with validateVar disabled",
			stdoutFormatVar:    "json",
			reportPath:         []string{"mock.json"},
			engineConfigVar:    engine.EngineConfig{},
			customRegexRuleVar: []string{},
			validateVar:        false,
			expectedPreRunErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdoutFormatVar = tt.stdoutFormatVar
			reportPathVar = tt.reportPath
			engineConfigVar = tt.engineConfigVar
			customRegexRuleVar = tt.customRegexRuleVar
			validateVar = tt.validateVar

			engineInstance, err := engine.Init(&engineConfigVar)
			if tt.expectedInitErr != nil {
				assert.ErrorIs(t, err, tt.expectedInitErr)
				return
			}
			rootCmd := &cobra.Command{
				Use:     "2ms",
				Short:   "2ms Secrets Detection",
				Long:    "2ms Secrets Detection: A tool to detect secrets in public websites and communication services.",
				Version: Version,
			}

			rootCmd.SetContext(context.WithValue(context.Background(), engineCtxKey, engineInstance))
			err = preRun(rootCmd, "mock", nil, nil)
			assert.ErrorIs(t, err, tt.expectedPreRunErr)

			// close(Channels.Items)
			// close(Channels.Errors)
			// Channels.WaitGroup.Wait()
			// assert.Empty(t, Channels.Errors)
		})
	}
}
