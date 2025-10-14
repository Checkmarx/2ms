package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTeamsWebhook(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "TeamsWebhook validation",
			truePositives: []string{
				"https://mycompany.webhook.office.com/webhookb2/qng7ps9c-b85g-ghvc-n8pj-e7cw4ohfwnfo@sdgxsaeg-7llf-f7ik-u76o-6mz0g4fpeu7v/IncomingWebhook/jcv8qamxgk8yzh7kw6scu9s8vukyohvo/pnxegvh3-ay4t-jrsu-078y-xeti6eg0i81e",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(TeamsWebhook())
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
