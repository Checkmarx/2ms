package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrivateAIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PrivateAIToken validation",
			truePositives: []string{
				"privateai_api_token = \"06m69x2a9p3vc7txwetpwvcmgzxvyjmu\"",
			},
			falsePositives: []string{
				`const privateaiToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(PrivateAIToken())
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
