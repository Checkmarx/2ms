package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMailgunPrivateAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "MailgunPrivateAPIToken validation",
			truePositives: []string{
				"var mailgunToken string = \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"mailgunToken := `key-c9739d56b3b4d24cac5963fef9ecc693`",
				"String mailgunToken = \"key-c9739d56b3b4d24cac5963fef9ecc693\";",
				"System.setProperty(\"MAILGUN_TOKEN\", \"key-c9739d56b3b4d24cac5963fef9ecc693\")",

				"mailgun_TOKEN = \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"mailgun_TOKEN :::= \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"mailgunToken=\"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"mailgunToken = \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"mailgunToken = key-c9739d56b3b4d24cac5963fef9ecc693",
				"mailgunToken = 'key-c9739d56b3b4d24cac5963fef9ecc693'",
				"mailgunToken = \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"  \"mailgunToken\" => \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"mailgun_TOKEN ::= \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"mailgunToken=key-c9739d56b3b4d24cac5963fef9ecc693",
				"{\n    \"mailgun_token\": \"key-c9739d56b3b4d24cac5963fef9ecc693\"\n}",
				"<mailgunToken>\n    key-c9739d56b3b4d24cac5963fef9ecc693\n</mailgunToken>",
				"string mailgunToken = \"key-c9739d56b3b4d24cac5963fef9ecc693\";",
				"mailgun_TOKEN ?= \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"{\"config.ini\": \"MAILGUN_TOKEN=key-c9739d56b3b4d24cac5963fef9ecc693\\nBACKUP_ENABLED=true\"}",
				"mailgun_token: key-c9739d56b3b4d24cac5963fef9ecc693",
				"mailgun_token: 'key-c9739d56b3b4d24cac5963fef9ecc693'",
				"mailgunToken := \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"var mailgunToken = \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"$mailgunToken .= \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"mailgun_TOKEN := \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
				"mailgun_token: \"key-c9739d56b3b4d24cac5963fef9ecc693\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(MailGunPrivateAPIToken())
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
