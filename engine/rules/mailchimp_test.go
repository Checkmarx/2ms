package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMailChimp(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "MailChimp validation",
			truePositives: []string{
				"mailchimpToken := \"900aec0106a460d8b402aa592ad69877-us20\"",
				"mailchimpToken := `900aec0106a460d8b402aa592ad69877-us20`",
				"mailchimpToken = '900aec0106a460d8b402aa592ad69877-us20'",
				"mailchimpToken = \"900aec0106a460d8b402aa592ad69877-us20\"",
				"mailchimpToken=\"900aec0106a460d8b402aa592ad69877-us20\"",
				"mailchimpToken=900aec0106a460d8b402aa592ad69877-us20",
				"mailchimpToken = 900aec0106a460d8b402aa592ad69877-us20",
				"<mailchimpToken>\n    900aec0106a460d8b402aa592ad69877-us20\n</mailchimpToken>",
				"var mailchimpToken = \"900aec0106a460d8b402aa592ad69877-us20\"",
				"$mailchimpToken .= \"900aec0106a460d8b402aa592ad69877-us20\"",
				"mailchimp_TOKEN ::= \"900aec0106a460d8b402aa592ad69877-us20\"",
				"mailchimp_TOKEN :::= \"900aec0106a460d8b402aa592ad69877-us20\"",
				"{\n    \"mailchimp_token\": \"900aec0106a460d8b402aa592ad69877-us20\"\n}",
				"mailchimp_token: '900aec0106a460d8b402aa592ad69877-us20'",
				"mailchimp_TOKEN = \"900aec0106a460d8b402aa592ad69877-us20\"",
				"mailchimp_TOKEN := \"900aec0106a460d8b402aa592ad69877-us20\"",
				"{\"config.ini\": \"MAILCHIMP_TOKEN=900aec0106a460d8b402aa592ad69877-us20\\nBACKUP_ENABLED=true\"}",
				"mailchimp_token: 900aec0106a460d8b402aa592ad69877-us20",
				"String mailchimpToken = \"900aec0106a460d8b402aa592ad69877-us20\";",
				"System.setProperty(\"MAILCHIMP_TOKEN\", \"900aec0106a460d8b402aa592ad69877-us20\")",
				"  \"mailchimpToken\" => \"900aec0106a460d8b402aa592ad69877-us20\"",
				"mailchimp_TOKEN ?= \"900aec0106a460d8b402aa592ad69877-us20\"",
				"mailchimpToken = \"900aec0106a460d8b402aa592ad69877-us20\"",
				"mailchimp_token: \"900aec0106a460d8b402aa592ad69877-us20\"",
				"string mailchimpToken = \"900aec0106a460d8b402aa592ad69877-us20\";",
				"var mailchimpToken string = \"900aec0106a460d8b402aa592ad69877-us20\"",
				`mailchimp_api_key: cefa780880ba5f5696192a34f6292c35-us18`, // gitleaks:allow
				`MAILCHIMPE_KEY = "b5b9f8e50c640da28993e8b6a48e3e53-us18"`, // gitleaks:allow
			},
			falsePositives: []string{
				// False Negative
				`MailchimpSDK.initialize(token: 3012a5754bbd716926f99c028f7ea428-us18)`, // gitleaks:allow
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(MailChimp())
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
