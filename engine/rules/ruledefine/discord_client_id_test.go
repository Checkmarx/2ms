package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscordClientID(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DiscordClientID validation",
			truePositives: []string{
				"discordToken=135616593581579345",
				"string discordToken = \"135616593581579345\";",
				"var discordToken string = \"135616593581579345\"",
				"discordToken = '135616593581579345'",
				"discord_TOKEN = \"135616593581579345\"",
				"discord_TOKEN := \"135616593581579345\"",
				"discordToken=\"135616593581579345\"",
				"{\n    \"discord_token\": \"135616593581579345\"\n}",
				"<discordToken>\n    135616593581579345\n</discordToken>",
				"discord_token: \"135616593581579345\"",
				"var discordToken = \"135616593581579345\"",
				"$discordToken .= \"135616593581579345\"",
				"discordToken = \"135616593581579345\"",
				"  \"discordToken\" => \"135616593581579345\"",
				"discordToken = \"135616593581579345\"",
				"discordToken = 135616593581579345",
				"discord_token: 135616593581579345",
				"String discordToken = \"135616593581579345\";",
				"discord_TOKEN ::= \"135616593581579345\"",
				"discord_TOKEN :::= \"135616593581579345\"",
				"{\"config.ini\": \"DISCORD_TOKEN=135616593581579345\\nBACKUP_ENABLED=true\"}",
				"discord_token: '135616593581579345'",
				"discordToken := \"135616593581579345\"",
				"discordToken := `135616593581579345`",
				"System.setProperty(\"DISCORD_TOKEN\", \"135616593581579345\")",
				"discord_TOKEN ?= \"135616593581579345\"",
			},
			falsePositives: []string{
				// Low entropy
				`discord=000000000000000000`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(DiscordClientID())
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
