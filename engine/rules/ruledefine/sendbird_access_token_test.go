package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendbirdAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SendbirdAccessToken validation",
			truePositives: []string{
				"var sendbirdToken string = \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"sendbirdToken := `a0038c8cadd21cf161ee31b3bd6b41789524a7e5`",
				"sendbirdToken = \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"System.setProperty(\"SENDBIRD_TOKEN\", \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\")",
				"  \"sendbirdToken\" => \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"sendbird_TOKEN := \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"sendbird_TOKEN :::= \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"sendbird_token: a0038c8cadd21cf161ee31b3bd6b41789524a7e5",
				"string sendbirdToken = \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\";",
				"sendbirdToken := \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"String sendbirdToken = \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\";",
				"sendbirdToken = 'a0038c8cadd21cf161ee31b3bd6b41789524a7e5'",
				"sendbird_TOKEN = \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"sendbird_TOKEN ::= \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"sendbird_TOKEN ?= \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"{\n    \"sendbird_token\": \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"\n}",
				"<sendbirdToken>\n    a0038c8cadd21cf161ee31b3bd6b41789524a7e5\n</sendbirdToken>",
				"sendbirdToken=\"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"sendbirdToken = \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"sendbirdToken=a0038c8cadd21cf161ee31b3bd6b41789524a7e5",
				"sendbirdToken = a0038c8cadd21cf161ee31b3bd6b41789524a7e5",
				"{\"config.ini\": \"SENDBIRD_TOKEN=a0038c8cadd21cf161ee31b3bd6b41789524a7e5\\nBACKUP_ENABLED=true\"}",
				"sendbird_token: 'a0038c8cadd21cf161ee31b3bd6b41789524a7e5'",
				"var sendbirdToken = \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"$sendbirdToken .= \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
				"sendbird_token: \"a0038c8cadd21cf161ee31b3bd6b41789524a7e5\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(SendbirdAccessToken())
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
