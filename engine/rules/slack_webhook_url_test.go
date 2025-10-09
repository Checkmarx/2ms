package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlackWebHookUrl(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SlackWebHookUrl validation",
			truePositives: []string{
				"hooks.slack.com/services/a6dpwxwqdin9u77pcurw9d7uqg3fu0fy68e68reo139g",
				"http://hooks.slack.com/services/a6dpwxwqdin9u77pcurw9d7uqg3fu0fy68e68reo139gj",
				"https://hooks.slack.com/services/a6dpwxwqdin9u77pcurw9d7uqg3fu0fy68e68reo139gjy",
				"http://hooks.slack.com/services/T024TTTTT/BBB72BBL/AZAAA9u0pA4ad666eMgbi555",
				"https://hooks.slack.com/services/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",
				"hooks.slack.com/workflows/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",
				"http://hooks.slack.com/workflows/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",
				"https://hooks.slack.com/workflows/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",
				"https://hooks.slack.com/workflows/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",
				"http://hooks.slack.com/workflows/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",
				"https://hooks.slack.com/triggers/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",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(SlackWebHookUrl())
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
