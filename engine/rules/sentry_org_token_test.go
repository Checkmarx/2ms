package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSentryOrgToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SentryOrgToken validation",
			truePositives: []string{
				"$sentryToken .= \"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\"",
				"sentryToken = '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'",
				"sentryToken = \"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\"",
				"System.setProperty(\"SENTRY_TOKEN\", \"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\")",
				"  \"sentryToken\" => \"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\"",
				"sentry_TOKEN = \"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\"",
				"{\"config.ini\": \"SENTRY_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"sentry_token: \"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\"",
				"string sentryToken = \"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\";",
				"sentryToken := \"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\"",
				"sentry_TOKEN :::= \"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\"",
				"sentry_TOKEN ?= \"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\"",
				"sentryToken = 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",
				"sentry_token: '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'",
				"sentryToken := `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`",
				"String sentryToken = \"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\";",
				"sentry_TOKEN := \"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\"",
				"sentry_TOKEN ::= \"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\"",
				"sentryToken=\"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\"",
				"sentryToken = \"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\"",
				"sentryToken=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",
				"{\n    \"sentry_token\": \"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\"\n}",
				"<sentryToken>\n    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\n</sentryToken>",
				"sentry_token: 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",
				"var sentryToken string = \"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\"",
				"var sentryToken = \"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\"",
				"sentryToken = \"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\"",
				"sentryToken := \"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\"",
				"$sentryToken .= \"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\"",
				"System.setProperty(\"SENTRY_TOKEN\", \"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\")",
				"sentry_TOKEN ::= \"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\"",
				"sentry_TOKEN :::= \"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\"",
				"sentryToken = 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",
				"sentryToken = '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'",
				"sentryToken = \"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\"",
				"  \"sentryToken\" => \"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\"",
				"{\n    \"sentry_token\": \"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\"\n}",
				"sentry_token: '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'",
				"string sentryToken = \"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\";",
				"String sentryToken = \"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\";",
				"sentry_TOKEN = \"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\"",
				"sentry_TOKEN := \"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\"",
				"sentry_TOKEN ?= \"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\"",
				"sentryToken=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",
				"{\"config.ini\": \"SENTRY_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"<sentryToken>\n    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\n</sentryToken>",
				"sentry_token: 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",
				"sentry_token: \"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\"",
				"var sentryToken string = \"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\"",
				"sentryToken := `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`",
				"var sentryToken = \"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\"",
				"sentryToken=\"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\"",
				" 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",
				"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",
				"<token>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</token>",
				"https://example.com?token=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&other=stuff",
			},
			falsePositives: []string{
				"sntrys_xKrM2VVU85FXrMOXWPGmpna37URVWU5tY7s6AbZyfbSkQv04VyRRb5OsSDfKTdkiFm1poIc87fUgrjTDppufvccUzB_ZpUH9HhYk73xTMa0BpDLEa1QaFUFo9Qlz0hnKTdTmVR",
				"sntrys_eyJpYXQiOjUxOCwidXJsIjoiaHR0cHM6Ly9RZ2lGZks5czhuIiwicmVnaW9uX3VybCI6Imh0dHBzOi8vdVoxU2dxeU5ZNTBHWjJlU0dWd2IiLCJvcmciOiJ0c25yayJ9_xKrM2VVU85FXrMOXWPGmpna37URVWU5tY7s6AbZyfb",
				"sntrys_eyJpYXQiOjUxOCwidXJsIjoiaHR0cHM6Ly9RZ2lGZks5czhuIiwicmVnaW9uX3VybCI6Imh0dHBzOi8vdVoxU2dxeU5ZNTBHWjJlU0dWd2IiLCJvcmciOiJ0c25yayJ9_xKrM2VVU85FXrMOXWPGmpna37URVWU5tY7s6AbZyfbSk",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("truePositives := []string{")
			for _, s := range tt.truePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			fmt.Println("falsePositives := []string{")
			for _, s := range tt.falsePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(SentryOrgToken())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for _, truePositive := range tt.truePositives {
				findings := d.DetectString(truePositive)
				assert.GreaterOrEqual(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			// validate false positives if any specified
			for _, falsePositive := range tt.falsePositives {
				findings := d.DetectString(falsePositive)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
