package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFacebookAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FacebookAccessToken validation",
			truePositives: []string{
				`{"facebook access_token":"911602140448729|AY-lRJZq9BoDLobvAiP25L7RcMg","token_type":"bearer"}`, // gitleaks:allow
				`facebook 1308742762612587|rhoK1cbv0DOU_RTX_87O4MkX7AI`,                                         // gitleaks:allow
				`facebook 1477036645700765|wRPf2v3mt2JfMqCLK8n7oltrEmc`,                                         // gitleaks:allow
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(FacebookAccessToken())
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
