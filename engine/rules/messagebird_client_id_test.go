package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessagebirdClientID(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "MessageBirdClientID validation",
			truePositives: []string{
				"MessageBirdToken=\"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"MessageBirdToken = 12345678-ABCD-ABCD-ABCD-1234567890AB",
				"string MessageBirdToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\";",
				"String MessageBirdToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\";",
				"$MessageBirdToken .= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"{\"config.ini\": \"MESSAGEBIRD_TOKEN=12345678-ABCD-ABCD-ABCD-1234567890AB\\nBACKUP_ENABLED=true\"}",
				"MessageBird_token: 12345678-ABCD-ABCD-ABCD-1234567890AB",
				"MessageBird_token: '12345678-ABCD-ABCD-ABCD-1234567890AB'",
				"var MessageBirdToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"MessageBird_TOKEN = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"MessageBird_TOKEN ::= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"MessageBirdToken=12345678-ABCD-ABCD-ABCD-1234567890AB",
				"{\n    \"MessageBird_token\": \"12345678-ABCD-ABCD-ABCD-1234567890AB\"\n}",
				"MessageBird_token: \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"var MessageBirdToken string = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"System.setProperty(\"MESSAGEBIRD_TOKEN\", \"12345678-ABCD-ABCD-ABCD-1234567890AB\")",
				"  \"MessageBirdToken\" => \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"MessageBird_TOKEN := \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"MessageBird_TOKEN :::= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"MessageBirdToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"<MessageBirdToken>\n    12345678-ABCD-ABCD-ABCD-1234567890AB\n</MessageBirdToken>",
				"MessageBirdToken := \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"MessageBirdToken := `12345678-ABCD-ABCD-ABCD-1234567890AB`",
				"MessageBirdToken = '12345678-ABCD-ABCD-ABCD-1234567890AB'",
				"MessageBirdToken = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"MessageBird_TOKEN ?= \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"const MessageBirdClientID = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(MessageBirdClientID())
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
