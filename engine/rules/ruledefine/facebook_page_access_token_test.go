package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFacebookPageAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FacebookPageAccessToken validation",
			truePositives: []string{
				`EAAM9GOnCB9kBO2frzOAWGN2zMnZClQshlWydZCrBNdodesbwimx1mfVJgqZBP5RSpMfUzWhtjTTXHG5I1UlvlwRZCgjm3ZBVGeTYiqAAoxyED6HaUdhpGVNoPUwAuAWWFsi9OvyYBQt22DGLqMIgD7VktuCTTZCWKasz81Q822FPhMTB9VFFyClNzQ0NLZClt9zxpsMMrUZCo1VU1rL3CKavir5QTfBjfCEzHNlWAUDUV2YZD`, // gitleaks:allow
				`EAAM9GOnCB9kBO2zXpAtRBmCrsPPjdA3KeBl4tqsEpcYd09cpjm9MZCBIklZBjIQBKGIJgFwm8IE17G5pipsfRBRBEHMWxvJsL7iHLUouiprxKRQfAagw8BEEDucceqxTiDhVW2IZAQNNbf0d1JhcapAGntx5S1Csm4j0GgZB3DuUfI2HJ9aViTtdfH2vjBy0wtpXm2iamevohGfoF4NgyRHusDLjqy91uYMkfrkc`,          // gitleaks:allow
				`- name: FACEBOOK_TOKEN
		value: "EAACEdEose0cBA1bad3afsf286JZCOV1XmV4NobAXqUXZA7U9F1UaaOdQZABvz73030MJoC3gGoQrE8IEoMl4gFA6MmQadlJQBqtRsgIcIhtelIJOJaew"`, // gitleaks:allow
			},
			falsePositives: []string{
				`eaaaC0b75a9329fded2ffa9a02b47e0117831b82`,
				`"strict-uri-encode@npm:^2.0.0":
  version: 2.0.0
  resolution: "strict-uri-encode@npm:2.0.0"
  checksum: eaac4cf978b6fbd480f1092cab8b233c9b949bcabfc9b598dd79a758f7243c28765ef7639c876fa72940dac687181b35486ea01ff7df3e65ce3848c64822c581
  languageName: node
  linkType: hard`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(FacebookPageAccessToken())
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
