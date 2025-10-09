package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlaidSecretKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PlaidSecretKey validation",
			truePositives: []string{
				"plaidToken=\"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"plaidToken=peruolj136x3u1reogkuyvc4ys0o2y",
				"{\n    \"plaid_token\": \"peruolj136x3u1reogkuyvc4ys0o2y\"\n}",
				"String plaidToken = \"peruolj136x3u1reogkuyvc4ys0o2y\";",
				"plaid_token: peruolj136x3u1reogkuyvc4ys0o2y",
				"plaid_token: 'peruolj136x3u1reogkuyvc4ys0o2y'",
				"plaid_token: \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"var plaidToken string = \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"plaidToken := `peruolj136x3u1reogkuyvc4ys0o2y`",
				"var plaidToken = \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"$plaidToken .= \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"plaidToken = 'peruolj136x3u1reogkuyvc4ys0o2y'",
				"plaidToken = \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"{\"config.ini\": \"PLAID_TOKEN=peruolj136x3u1reogkuyvc4ys0o2y\\nBACKUP_ENABLED=true\"}",
				"plaidToken := \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"System.setProperty(\"PLAID_TOKEN\", \"peruolj136x3u1reogkuyvc4ys0o2y\")",
				"  \"plaidToken\" => \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"plaid_TOKEN = \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"plaid_TOKEN := \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"plaid_TOKEN :::= \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"plaidToken = peruolj136x3u1reogkuyvc4ys0o2y",
				"<plaidToken>\n    peruolj136x3u1reogkuyvc4ys0o2y\n</plaidToken>",
				"string plaidToken = \"peruolj136x3u1reogkuyvc4ys0o2y\";",
				"plaidToken = \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"plaid_TOKEN ::= \"peruolj136x3u1reogkuyvc4ys0o2y\"",
				"plaid_TOKEN ?= \"peruolj136x3u1reogkuyvc4ys0o2y\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(PlaidSecretKey())
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
