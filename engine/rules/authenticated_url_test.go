package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticatedURL(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "AuthenticatedURL validation",
			truePositives: []string{
				"https://token12345abcdef:unused@hooks.slack.com/services/T000/B000/XXXX",
				"https://user123:myStrongP@ssw0rd@registry.example.com/v2/",
				"https://AKIAIOSFODNN7EXAMPLE:abcd1234@aws.amazon.com/bucket/data",
				"https://admin:SuperSecret123@myapp.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(AuthenticatedURL())
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
