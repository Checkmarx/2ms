package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMailgunSigningKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "MailGunSigningKey validation",
			truePositives: []string{
				"mailgun_TOKEN ?= \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"mailgunToken=55402e65a5c84545c151e393ea9e81a4-00001111-22223333",
				"mailgunToken = 55402e65a5c84545c151e393ea9e81a4-00001111-22223333",
				"mailgun_token: '55402e65a5c84545c151e393ea9e81a4-00001111-22223333'",
				"mailgun_token: \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"string mailgunToken = \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\";",
				"String mailgunToken = \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\";",
				"$mailgunToken .= \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"mailgunToken = '55402e65a5c84545c151e393ea9e81a4-00001111-22223333'",
				"mailgunToken = \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"{\n    \"mailgun_token\": \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"\n}",
				"{\"config.ini\": \"MAILGUN_TOKEN=55402e65a5c84545c151e393ea9e81a4-00001111-22223333\\nBACKUP_ENABLED=true\"}",
				"mailgunToken := \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"var mailgunToken = \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"  \"mailgunToken\" => \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"mailgun_TOKEN ::= \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"mailgun_token: 55402e65a5c84545c151e393ea9e81a4-00001111-22223333",
				"var mailgunToken string = \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"mailgunToken := `55402e65a5c84545c151e393ea9e81a4-00001111-22223333`",
				"mailgunToken = \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"System.setProperty(\"MAILGUN_TOKEN\", \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\")",
				"mailgun_TOKEN = \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"mailgunToken=\"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"<mailgunToken>\n    55402e65a5c84545c151e393ea9e81a4-00001111-22223333\n</mailgunToken>",
				"mailgun_TOKEN := \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
				"mailgun_TOKEN :::= \"55402e65a5c84545c151e393ea9e81a4-00001111-22223333\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(MailGunSigningKey())
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
