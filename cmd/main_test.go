package cmd

import (
	"os"
	"testing"
	"time"

	"github.com/checkmarx/2ms/v4/engine"
	"github.com/checkmarx/2ms/v4/internal/resources"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestPreRun(t *testing.T) {
	tests := []struct {
		name              string
		stdoutFormatVar   string
		reportPath        []string
		engineConfigVar   engine.EngineConfig
		expectedInitErr   error
		expectedPreRunErr error
	}{
		{
			name:              "error in validateFormat",
			stdoutFormatVar:   "invalid",
			reportPath:        []string{"report.json"},
			engineConfigVar:   engine.EngineConfig{},
			expectedPreRunErr: errInvalidOutputFormat,
		},
		{
			name:            "error in engine.Init",
			stdoutFormatVar: "json",
			reportPath:      []string{"mock.json"},
			engineConfigVar: engine.EngineConfig{
				SelectedList: []string{"mockInvalid"},
			},
			expectedInitErr: engine.ErrNoRulesSelected,
		},
		{
			name:            "successfully started go routines with validateVar enabled",
			stdoutFormatVar: "json",
			reportPath:      []string{"mock.json"},
			engineConfigVar: engine.EngineConfig{
				ScanConfig: resources.ScanConfig{
					WithValidation: true,
				},
			},
			expectedPreRunErr: nil,
		},
		{
			name:              "successfully started go routines with validateVar disabled",
			stdoutFormatVar:   "json",
			reportPath:        []string{"mock.json"},
			engineConfigVar:   engine.EngineConfig{},
			expectedPreRunErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdoutFormatVar = tt.stdoutFormatVar
			reportPathVar = tt.reportPath
			engineConfigVar = tt.engineConfigVar

			engineInstance, err := engine.Init(&engineConfigVar)
			if tt.expectedInitErr != nil {
				assert.ErrorIs(t, err, tt.expectedInitErr)
				return
			}
			defer engineInstance.Shutdown()
			rootCmd := &cobra.Command{
				Use:     "2ms",
				Short:   "2ms Secrets Detection",
				Long:    "2ms Secrets Detection: A tool to detect secrets in public websites and communication services.",
				Version: Version,
			}

			time.AfterFunc(50*time.Millisecond, func() {
				close(engineInstance.GetPluginChannels().GetItemsCh())
			})
			err = preRun("mock", engineInstance, rootCmd, nil)
			assert.ErrorIs(t, err, tt.expectedPreRunErr)
		})
	}
}
