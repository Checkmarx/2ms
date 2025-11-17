package cmd

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/checkmarx/2ms/v4/engine"
	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
	"github.com/checkmarx/2ms/v4/internal/resources"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestPreRun(t *testing.T) {
	tests := []struct {
		name                     string
		stdoutFormatVar          string
		reportPath               []string
		engineConfigVar          engine.EngineConfig
		expectedInitErr          error   // alternatively, use expectedContainsInitErrs
		expectedContainsInitErrs []error // alternatively, use expectedInitErr
		expectedPreRunErr        error
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
		{
			name: "errors on custom rules, rule name, id, regex missing",
			engineConfigVar: engine.EngineConfig{
				CustomRules: []*ruledefine.Rule{
					{
						Description: "Match passwords",
					},
					{
						RuleID:      "b47a1995-6572-41bb-b01d-d215b43ab089",
						RuleName:    "mock-rule2",
						Description: "Match API keys",
						Regex:       "[A-Za-z0-9]{40}",
					},
				},
			},
			expectedPreRunErr: nil,
			expectedContainsInitErrs: []error{
				fmt.Errorf("rule#0: missing ruleID"),
				fmt.Errorf("rule#0: missing ruleName"),
				fmt.Errorf("rule#0: missing regex"),
			},
		},
		{
			name: "errors on custom rules, regex, severity and score parameters invalid",
			engineConfigVar: engine.EngineConfig{
				CustomRules: []*ruledefine.Rule{
					{
						RuleID:      "db18ccf1-4fbf-49f6-aec1-939a2e5464c0",
						RuleName:    "mock-rule",
						Description: "Match passwords",
						Regex:       "[A-Za-z0-9]{32})",
						Severity:    "mockSeverity",
						ScoreParameters: ruledefine.ScoreParameters{
							Category: "mockCategory",
							RuleType: 10,
						},
					},
					{
						RuleID:      "b47a1995-6572-41bb-b01d-d215b43ab089",
						RuleName:    "mock-rule2",
						Description: "Match API keys",
						Regex:       "[A-Za-z0-9]{40}",
					},
				},
			},
			expectedPreRunErr: nil,
			expectedContainsInitErrs: []error{
				fmt.Errorf("rule#0;RuleID-db18ccf1-4fbf-49f6-aec1-939a2e5464c0: invalid regex"),
				fmt.Errorf("rule#0;RuleID-db18ccf1-4fbf-49f6-aec1-939a2e5464c0: invalid severity:" +
					" mockSeverity not one of ([Critical High Medium Low Info])"),
				fmt.Errorf("rule#0;RuleID-db18ccf1-4fbf-49f6-aec1-939a2e5464c0: invalid category:" +
					" mockCategory not an acceptable category of type RuleCategory"),
				fmt.Errorf("rule#0;RuleID-db18ccf1-4fbf-49f6-aec1-939a2e5464c0: invalid rule type: 10 not an acceptable uint8 value, maximum is 4"),
			},
		},
		{
			name: "errors on custom rules, rule id missing",
			engineConfigVar: engine.EngineConfig{
				CustomRules: []*ruledefine.Rule{
					{
						RuleName:    "mock-rule",
						Description: "Match passwords",
						Regex:       "[A-Za-z0-9]{32})",
					},
					{
						RuleName:    "mock-rule2",
						Description: "Match API keys",
						Regex:       "[A-Za-z0-9]{40}",
					},
				},
			},
			expectedPreRunErr: nil,
			expectedContainsInitErrs: []error{
				fmt.Errorf("rule#0;RuleName-mock-rule: missing ruleID"),
				fmt.Errorf("rule#1;RuleName-mock-rule2: missing ruleID"),
			},
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
			for _, expectErr := range tt.expectedContainsInitErrs {
				assert.ErrorContains(t, err, expectErr.Error())
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

// TODO temporary, move it to organized integrations tests later
func TestVersionFlagExitZero(t *testing.T) {
	// Preserve and restore process globals altered in the test.
	oldArgs := os.Args
	t.Cleanup(func() {
		os.Args = oldArgs
	})

	// Simulate: 2ms --version
	os.Args = []string{"2ms", "--version"}

	code, err := Execute()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got: %d", code)
	}
}
