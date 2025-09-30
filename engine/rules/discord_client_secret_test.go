package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscordClientSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DiscordClientSecret validation",
			truePositives: []string{
				"  \"discordToken\" => \"60210628263064570884093939025160\"",
				"discord_TOKEN ?= \"60210628263064570884093939025160\"",
				"discord_token: \"60210628263064570884093939025160\"",
				"discordToken := \"60210628263064570884093939025160\"",
				"$discordToken .= \"60210628263064570884093939025160\"",
				"discordToken = '60210628263064570884093939025160'",
				"System.setProperty(\"DISCORD_TOKEN\", \"60210628263064570884093939025160\")",
				"discord_TOKEN = \"60210628263064570884093939025160\"",
				"discord_TOKEN := \"60210628263064570884093939025160\"",
				"discord_TOKEN :::= \"60210628263064570884093939025160\"",
				"discordToken=\"60210628263064570884093939025160\"",
				"discordToken = \"60210628263064570884093939025160\"",
				"{\n    \"discord_token\": \"60210628263064570884093939025160\"\n}",
				"{\"config.ini\": \"DISCORD_TOKEN=60210628263064570884093939025160\\nBACKUP_ENABLED=true\"}",
				"discord_token: 60210628263064570884093939025160",
				"discord_token: '60210628263064570884093939025160'",
				"var discordToken string = \"60210628263064570884093939025160\"",
				"discordToken = \"60210628263064570884093939025160\"",
				"discordToken=60210628263064570884093939025160",
				"discordToken := `60210628263064570884093939025160`",
				"var discordToken = \"60210628263064570884093939025160\"",
				"discord_TOKEN ::= \"60210628263064570884093939025160\"",
				"discordToken = 60210628263064570884093939025160",
				"<discordToken>\n    60210628263064570884093939025160\n</discordToken>",
				"string discordToken = \"60210628263064570884093939025160\";",
				"String discordToken = \"60210628263064570884093939025160\";",
			},
			falsePositives: []string{
				// Low entropy
				`discord=00000000000000000000000000000000`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("truePositives := []string{")
			for _, s := range tt.truePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			fmt.Println("falsePositives := []string{")
			for _, s := range tt.falsePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(DiscordClientSecret())
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
