package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZendeskSecretKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ZendeskSecretKey validation",
			truePositives: []string{
				"zendesk_token: \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendeskToken := `18ife5hrbego7clzhdc995q07xjvcd9jadm65ule`",
				"zendeskToken = \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"<zendeskToken>\n    18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\n</zendeskToken>",
				"var zendeskToken = \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendeskToken = '18ife5hrbego7clzhdc995q07xjvcd9jadm65ule'",
				"zendesk_TOKEN := \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendesk_TOKEN ::= \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendesk_TOKEN :::= \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendeskToken = \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendeskToken := \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"String zendeskToken = \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\";",
				"System.setProperty(\"ZENDESK_TOKEN\", \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\")",
				"zendesk_TOKEN = \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendesk_TOKEN ?= \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendeskToken=\"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendesk_token: 18ife5hrbego7clzhdc995q07xjvcd9jadm65ule",
				"string zendeskToken = \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\";",
				"var zendeskToken string = \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"$zendeskToken .= \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"  \"zendeskToken\" => \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"",
				"zendeskToken=18ife5hrbego7clzhdc995q07xjvcd9jadm65ule",
				"zendeskToken = 18ife5hrbego7clzhdc995q07xjvcd9jadm65ule",
				"{\n    \"zendesk_token\": \"18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\"\n}",
				"{\"config.ini\": \"ZENDESK_TOKEN=18ife5hrbego7clzhdc995q07xjvcd9jadm65ule\\nBACKUP_ENABLED=true\"}",
				"zendesk_token: '18ife5hrbego7clzhdc995q07xjvcd9jadm65ule'",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(ZendeskSecretKey())
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
