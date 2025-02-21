package cmd

import (
	"fmt"
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
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
			expectedErr:        fmt.Errorf("invalid output format: invalid, available formats are: json, yaml and sarif"),
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
			expectedErr:        fmt.Errorf("no rules were selected"),
		},
		{
			name:               "error in engine.AddRegexRules",
			stdoutFormatVar:    "json",
			reportPath:         []string{"mock.json"},
			engineConfigVar:    engine.EngineConfig{},
			customRegexRuleVar: []string{"[a-z"},
			validateVar:        false,
			expectedErr:        fmt.Errorf("failed to compile regex rule [a-z: error parsing regexp: missing closing ]: `[a-z`"),
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
			Channels.Items = make(chan plugins.ISourceItem)
			Channels.Errors = make(chan error)
			Channels.WaitGroup = &sync.WaitGroup{}
			secretsChan = make(chan *secrets.Secret)
			secretsExtrasChan = make(chan *secrets.Secret)
			validationChan = make(chan *secrets.Secret)
			cvssScoreWithoutValidationChan = make(chan *secrets.Secret)
			err := preRun("mock", nil, nil)
			close(Channels.Items)
			close(Channels.Errors)
			Channels.WaitGroup.Wait()
			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.expectedErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Empty(t, Channels.Errors)
			}
		})
	}
}
