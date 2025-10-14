package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlaidAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PlaidAccessToken validation",
			truePositives: []string{

				"plaid_TOKEN ::= \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaidToken = \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"{\"config.ini\": \"PLAID_TOKEN=access-development-0b686395-8a68-e27f-13f6-56230b647a0c\\nBACKUP_ENABLED=true\"}",
				"plaid_token: access-development-0b686395-8a68-e27f-13f6-56230b647a0c",
				"plaid_token: \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"var plaidToken string = \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaidToken := \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaid_TOKEN = \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaid_TOKEN :::= \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaidToken = access-development-0b686395-8a68-e27f-13f6-56230b647a0c",
				"{\n    \"plaid_token\": \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"\n}",
				"String plaidToken = \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\";",
				"System.setProperty(\"PLAID_TOKEN\", \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\")",
				"  \"plaidToken\" => \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaidToken=access-development-0b686395-8a68-e27f-13f6-56230b647a0c",
				"<plaidToken>\n    access-development-0b686395-8a68-e27f-13f6-56230b647a0c\n</plaidToken>",
				"var plaidToken = \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"$plaidToken .= \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaid_TOKEN ?= \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaidToken=\"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaid_token: 'access-development-0b686395-8a68-e27f-13f6-56230b647a0c'",
				"string plaidToken = \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\";",
				"plaidToken := `access-development-0b686395-8a68-e27f-13f6-56230b647a0c`",
				"plaidToken = 'access-development-0b686395-8a68-e27f-13f6-56230b647a0c'",
				"plaidToken = \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
				"plaid_TOKEN := \"access-development-0b686395-8a68-e27f-13f6-56230b647a0c\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(PlaidAccessToken())
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
