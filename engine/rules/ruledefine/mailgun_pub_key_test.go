package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMailgunPubKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "MailGunPubAPIToken validation",
			truePositives: []string{
				"mailgunToken := \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"String mailgunToken = \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\";",
				"System.setProperty(\"MAILGUN_TOKEN\", \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\")",
				"mailgunToken=\"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgunToken = \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgun_token: pubkey-3eacf6a44c6da2640c0779535f43e2e1",
				"mailgun_token: 'pubkey-3eacf6a44c6da2640c0779535f43e2e1'",
				"  \"mailgunToken\" => \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgun_TOKEN = \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgun_TOKEN := \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgunToken = pubkey-3eacf6a44c6da2640c0779535f43e2e1",
				"{\"config.ini\": \"MAILGUN_TOKEN=pubkey-3eacf6a44c6da2640c0779535f43e2e1\\nBACKUP_ENABLED=true\"}",
				"var mailgunToken string = \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgun_TOKEN ::= \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgun_TOKEN :::= \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgun_TOKEN ?= \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgunToken=pubkey-3eacf6a44c6da2640c0779535f43e2e1",
				"{\n    \"mailgun_token\": \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"\n}",
				"string mailgunToken = \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\";",
				"mailgunToken := `pubkey-3eacf6a44c6da2640c0779535f43e2e1`",
				"var mailgunToken = \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"$mailgunToken .= \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"mailgunToken = 'pubkey-3eacf6a44c6da2640c0779535f43e2e1'",
				"mailgunToken = \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
				"<mailgunToken>\n    pubkey-3eacf6a44c6da2640c0779535f43e2e1\n</mailgunToken>",
				"mailgun_token: \"pubkey-3eacf6a44c6da2640c0779535f43e2e1\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(MailGunPubAPIToken())
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
