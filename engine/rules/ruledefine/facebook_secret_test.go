package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFacebookSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FacebookSecret validation",
			truePositives: []string{
				"$facebookToken .= \"cab992005971b4a8f0a4c494b4f34182\"",
				"  \"facebookToken\" => \"cab992005971b4a8f0a4c494b4f34182\"",
				"facebook_TOKEN = \"cab992005971b4a8f0a4c494b4f34182\"",
				"facebook_TOKEN :::= \"cab992005971b4a8f0a4c494b4f34182\"",
				"facebookToken=cab992005971b4a8f0a4c494b4f34182",
				"facebookToken = cab992005971b4a8f0a4c494b4f34182",
				"<facebookToken>\n    cab992005971b4a8f0a4c494b4f34182\n</facebookToken>",
				"facebook_token: cab992005971b4a8f0a4c494b4f34182",
				"facebookToken = \"cab992005971b4a8f0a4c494b4f34182\"",
				"facebook_TOKEN ?= \"cab992005971b4a8f0a4c494b4f34182\"",
				"facebookToken=\"cab992005971b4a8f0a4c494b4f34182\"",
				"{\n    \"facebook_token\": \"cab992005971b4a8f0a4c494b4f34182\"\n}",
				"string facebookToken = \"cab992005971b4a8f0a4c494b4f34182\";",
				"facebookToken := \"cab992005971b4a8f0a4c494b4f34182\"",
				"facebookToken = 'cab992005971b4a8f0a4c494b4f34182'",
				"System.setProperty(\"FACEBOOK_TOKEN\", \"cab992005971b4a8f0a4c494b4f34182\")",
				"facebook_TOKEN := \"cab992005971b4a8f0a4c494b4f34182\"",
				"facebookToken = \"cab992005971b4a8f0a4c494b4f34182\"",
				"{\"config.ini\": \"FACEBOOK_TOKEN=cab992005971b4a8f0a4c494b4f34182\\nBACKUP_ENABLED=true\"}",
				"facebook_token: 'cab992005971b4a8f0a4c494b4f34182'",
				"facebook_token: \"cab992005971b4a8f0a4c494b4f34182\"",
				"facebookToken := `cab992005971b4a8f0a4c494b4f34182`",
				"String facebookToken = \"cab992005971b4a8f0a4c494b4f34182\";",
				"facebook_TOKEN ::= \"cab992005971b4a8f0a4c494b4f34182\"",
				"var facebookToken string = \"cab992005971b4a8f0a4c494b4f34182\"",
				"var facebookToken = \"cab992005971b4a8f0a4c494b4f34182\"",
				"facebook_app_secret = \"6dca6432e45d933e13650d1882bd5e69\"",
				"facebook_client_access_token: 26f5fd13099f2c1331aafb86f6489692",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(FacebookSecret())
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
