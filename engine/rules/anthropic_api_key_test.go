package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnthropicApiKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "AnthropicApiKey validation",
			truePositives: []string{
				"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
				"anthropic_api_token = \"sk-ant-api03-9o_neoo9xht6ph4jl3h_6merrf5ttijdwt6253ikkhh165l26eny99q13f6_hcolmofa64v4a6gdnu8sbgwypfmnq8u1zAA\"",
			},
			falsePositives: []string{
				// Too short key (missing characters)
				"sk-ant-api03-abc123xyz-456de-klMnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA",
				// Wrong suffix
				"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzBB",
				// Wrong prefix (admin key, not API key)
				"sk-ant-admin01-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(AnthropicApiKey())
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
