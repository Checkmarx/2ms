package cmd

import (
	"testing"

	"github.com/checkmarx/2ms/v4/engine"
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
		expectedErr        error
	}{
		{
			name:               "error in validateFormat",
			stdoutFormatVar:    "invalid",
			reportPath:         []string{"report.json"},
			engineConfigVar:    engine.EngineConfig{},
			customRegexRuleVar: []string{},
			validateVar:        false,
			expectedErr:        errInvalidOutputFormat,
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
			expectedErr:        engine.ErrNoRulesSelected,
		},
		{
			name:               "error in engine.AddRegexRules",
			stdoutFormatVar:    "json",
			reportPath:         []string{"mock.json"},
			engineConfigVar:    engine.EngineConfig{},
			customRegexRuleVar: []string{"[a-z"},
			validateVar:        false,
			expectedErr:        engine.ErrFailedToCompileRegexRule,
		},
		{
			name:               "successfully started go routines with validateVar enabled",
			stdoutFormatVar:    "json",
			reportPath:         []string{"mock.json"},
			engineConfigVar:    engine.EngineConfig{},
			customRegexRuleVar: []string{},
			validateVar:        true,
			expectedErr:        nil,
		},
		{
			name:               "successfully started go routines with validateVar disabled",
			stdoutFormatVar:    "json",
			reportPath:         []string{"mock.json"},
			engineConfigVar:    engine.EngineConfig{},
			customRegexRuleVar: []string{},
			validateVar:        false,
			expectedErr:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdoutFormatVar = tt.stdoutFormatVar
			reportPathVar = tt.reportPath
			engineConfigVar = tt.engineConfigVar
			customRegexRuleVar = tt.customRegexRuleVar
			validateVar = tt.validateVar
			err := preRun("mock", nil, nil)
			assert.ErrorIs(t, err, tt.expectedErr)

			// close(Channels.Items)
			// close(Channels.Errors)
			// Channels.WaitGroup.Wait()
			// assert.Empty(t, Channels.Errors)
		})
	}
}
