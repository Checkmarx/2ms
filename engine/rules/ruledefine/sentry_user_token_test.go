package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
)

func TestSentryUserToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name:          "SentryUserToken validation",
			truePositives: utils.GenerateSampleSecrets("sentry", secrets.NewSecret(`sntryu_[a-f0-9]{64}`)),
			falsePositives: []string{
				secrets.NewSecret(`sntryu_[a-f0-9]{63}`), // too short
				secrets.NewSecret(`sntryu_[a-f0-9]{65}`), // too long
				secrets.NewSecret(`sntryu_[a]{64}`),      // low entropy},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(SentryUserToken())
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
