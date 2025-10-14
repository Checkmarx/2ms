package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscordAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DiscordApiToken validation",
			truePositives: []string{
				"$discordToken .= \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"discordToken = \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"  \"discordToken\" => \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"discord_TOKEN ?= \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"discordToken=\"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"{\n    \"discord_token\": \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"\n}",
				"discord_token: \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"string discordToken = \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\";",
				"discordToken := \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"discord_TOKEN ::= \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"discord_TOKEN :::= \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"discordToken = eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a",
				"discord_token: eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a",
				"discord_token: 'eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a'",
				"discordToken := `eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a`",
				"var discordToken = \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"discordToken = 'eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a'",
				"discordToken = \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"discordToken=eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a",
				"{\"config.ini\": \"DISCORD_TOKEN=eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\\nBACKUP_ENABLED=true\"}",
				"<discordToken>\n    eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\n</discordToken>",
				"System.setProperty(\"DISCORD_TOKEN\", \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\")",
				"discord_TOKEN = \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"discord_TOKEN := \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"var discordToken string = \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\"",
				"String discordToken = \"eaa48d2cb6ca5a848fece5197048b20a80af5afda77d32a30eeed9e80a4fc30a\";",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(DiscordAPIToken())
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
