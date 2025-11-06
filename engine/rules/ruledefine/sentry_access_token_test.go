package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSentryAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SentryAccessToken validation",
			truePositives: []string{
				"<sentryToken>\n    777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\n</sentryToken>",
				"sentry_token: 777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac",
				"var sentryToken string = \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"String sentryToken = \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\";",
				"sentry_TOKEN = \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"sentry_TOKEN :::= \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"sentryToken=\"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"sentryToken = \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"sentryToken=777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac",
				"sentry_token: '777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac'",
				"var sentryToken = \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"sentryToken = \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"System.setProperty(\"SENTRY_TOKEN\", \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\")",
				"sentry_TOKEN := \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"sentryToken = 777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac",
				"{\n    \"sentry_token\": \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"\n}",
				"{\"config.ini\": \"SENTRY_TOKEN=777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\\nBACKUP_ENABLED=true\"}",
				"sentry_token: \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"string sentryToken = \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\";",
				"sentryToken := \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"$sentryToken .= \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"sentry_TOKEN ::= \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"sentryToken := `777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac`",
				"sentryToken = '777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac'",
				"  \"sentryToken\" => \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
				"sentry_TOKEN ?= \"777d2c339c23c3ff67f14519a66cac8822e4e8573e88c8c4a0720d6e2179bfac\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(SentryAccessToken())
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
