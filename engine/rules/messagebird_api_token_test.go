package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessagebirdAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "MessageBirdAPIToken validation",
			truePositives: []string{
				"messagebird_TOKEN ?= \"v6300i0eqyif6mib1x9ek2fma\"",
				"messagebirdToken=\"v6300i0eqyif6mib1x9ek2fma\"",
				"messagebirdToken = \"v6300i0eqyif6mib1x9ek2fma\"",
				"messagebirdToken = v6300i0eqyif6mib1x9ek2fma",
				"{\"config.ini\": \"MESSAGEBIRD_TOKEN=v6300i0eqyif6mib1x9ek2fma\\nBACKUP_ENABLED=true\"}",
				"<messagebirdToken>\n    v6300i0eqyif6mib1x9ek2fma\n</messagebirdToken>",
				"messagebird_token: 'v6300i0eqyif6mib1x9ek2fma'",
				"string messagebirdToken = \"v6300i0eqyif6mib1x9ek2fma\";",
				"messagebirdToken := \"v6300i0eqyif6mib1x9ek2fma\"",
				"var messagebirdToken = \"v6300i0eqyif6mib1x9ek2fma\"",
				"messagebirdToken = 'v6300i0eqyif6mib1x9ek2fma'",
				"System.setProperty(\"MESSAGEBIRD_TOKEN\", \"v6300i0eqyif6mib1x9ek2fma\")",
				"messagebird_TOKEN ::= \"v6300i0eqyif6mib1x9ek2fma\"",
				"messagebirdToken=v6300i0eqyif6mib1x9ek2fma",
				"{\n    \"messagebird_token\": \"v6300i0eqyif6mib1x9ek2fma\"\n}",
				"messagebird_token: v6300i0eqyif6mib1x9ek2fma",
				"messagebird_token: \"v6300i0eqyif6mib1x9ek2fma\"",
				"String messagebirdToken = \"v6300i0eqyif6mib1x9ek2fma\";",
				"$messagebirdToken .= \"v6300i0eqyif6mib1x9ek2fma\"",
				"messagebirdToken = \"v6300i0eqyif6mib1x9ek2fma\"",
				"  \"messagebirdToken\" => \"v6300i0eqyif6mib1x9ek2fma\"",
				"var messagebirdToken string = \"v6300i0eqyif6mib1x9ek2fma\"",
				"messagebirdToken := `v6300i0eqyif6mib1x9ek2fma`",
				"messagebird_TOKEN = \"v6300i0eqyif6mib1x9ek2fma\"",
				"messagebird_TOKEN := \"v6300i0eqyif6mib1x9ek2fma\"",
				"messagebird_TOKEN :::= \"v6300i0eqyif6mib1x9ek2fma\"",
				"message-bird_TOKEN = \"v6300i0eqyif6mib1x9ek2fma\"",
				"message-bird_TOKEN ?= \"v6300i0eqyif6mib1x9ek2fma\"",
				"message-birdToken = \"v6300i0eqyif6mib1x9ek2fma\"",
				"{\n    \"message-bird_token\": \"v6300i0eqyif6mib1x9ek2fma\"\n}",
				"<message-birdToken>\n    v6300i0eqyif6mib1x9ek2fma\n</message-birdToken>",
				"message-bird_token: 'v6300i0eqyif6mib1x9ek2fma'",
				"message-birdToken := \"v6300i0eqyif6mib1x9ek2fma\"",
				"System.setProperty(\"MESSAGE-BIRD_TOKEN\", \"v6300i0eqyif6mib1x9ek2fma\")",
				"message-birdToken=v6300i0eqyif6mib1x9ek2fma",
				"{\"config.ini\": \"MESSAGE-BIRD_TOKEN=v6300i0eqyif6mib1x9ek2fma\\nBACKUP_ENABLED=true\"}",
				"String message-birdToken = \"v6300i0eqyif6mib1x9ek2fma\";",
				"message-birdToken = 'v6300i0eqyif6mib1x9ek2fma'",
				"message-birdToken = \"v6300i0eqyif6mib1x9ek2fma\"",
				"  \"message-birdToken\" => \"v6300i0eqyif6mib1x9ek2fma\"",
				"message-bird_TOKEN ::= \"v6300i0eqyif6mib1x9ek2fma\"",
				"message-bird_token: v6300i0eqyif6mib1x9ek2fma",
				"string message-birdToken = \"v6300i0eqyif6mib1x9ek2fma\";",
				"var message-birdToken = \"v6300i0eqyif6mib1x9ek2fma\"",
				"message-bird_TOKEN := \"v6300i0eqyif6mib1x9ek2fma\"",
				"message-bird_TOKEN :::= \"v6300i0eqyif6mib1x9ek2fma\"",
				"message-birdToken=\"v6300i0eqyif6mib1x9ek2fma\"",
				"message-birdToken = v6300i0eqyif6mib1x9ek2fma",
				"message-bird_token: \"v6300i0eqyif6mib1x9ek2fma\"",
				"var message-birdToken string = \"v6300i0eqyif6mib1x9ek2fma\"",
				"message-birdToken := `v6300i0eqyif6mib1x9ek2fma`",
				"$message-birdToken .= \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_birdToken=v6300i0eqyif6mib1x9ek2fma",
				"message_bird_token: 'v6300i0eqyif6mib1x9ek2fma'",
				"String message_birdToken = \"v6300i0eqyif6mib1x9ek2fma\";",
				"message_birdToken = \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_bird_TOKEN ?= \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_birdToken=\"v6300i0eqyif6mib1x9ek2fma\"",
				"message_birdToken = \"v6300i0eqyif6mib1x9ek2fma\"",
				"{\n    \"message_bird_token\": \"v6300i0eqyif6mib1x9ek2fma\"\n}",
				"{\"config.ini\": \"MESSAGE_BIRD_TOKEN=v6300i0eqyif6mib1x9ek2fma\\nBACKUP_ENABLED=true\"}",
				"<message_birdToken>\n    v6300i0eqyif6mib1x9ek2fma\n</message_birdToken>",
				"message_bird_token: v6300i0eqyif6mib1x9ek2fma",
				"var message_birdToken string = \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_birdToken := \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_bird_token: \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_birdToken := `v6300i0eqyif6mib1x9ek2fma`",
				"var message_birdToken = \"v6300i0eqyif6mib1x9ek2fma\"",
				"$message_birdToken .= \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_birdToken = 'v6300i0eqyif6mib1x9ek2fma'",
				"System.setProperty(\"MESSAGE_BIRD_TOKEN\", \"v6300i0eqyif6mib1x9ek2fma\")",
				"  \"message_birdToken\" => \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_bird_TOKEN := \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_birdToken = v6300i0eqyif6mib1x9ek2fma",
				"string message_birdToken = \"v6300i0eqyif6mib1x9ek2fma\";",
				"message_bird_TOKEN = \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_bird_TOKEN ::= \"v6300i0eqyif6mib1x9ek2fma\"",
				"message_bird_TOKEN :::= \"v6300i0eqyif6mib1x9ek2fma\"",
			},
			falsePositives: []string{},
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
			rule := ConvertNewRuleToGitleaksRule(MessageBirdAPIToken())
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
