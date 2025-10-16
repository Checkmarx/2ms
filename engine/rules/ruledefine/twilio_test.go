package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTwilio(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Twilio validation",
			truePositives: []string{
				"twilioToken = SK992be1adebe83f2ff461ef660e5f65d6",
				"{\"config.ini\": \"TWILIO_TOKEN=SK992be1adebe83f2ff461ef660e5f65d6\\nBACKUP_ENABLED=true\"}",
				"twilio_token: \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"string twilioToken = \"SK992be1adebe83f2ff461ef660e5f65d6\";",
				"var twilioToken string = \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"twilioToken := \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"var twilioToken = \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"twilio_TOKEN := \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"{\n    \"twilio_token\": \"SK992be1adebe83f2ff461ef660e5f65d6\"\n}",
				"twilioToken := `SK992be1adebe83f2ff461ef660e5f65d6`",
				"twilio_TOKEN ?= \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"twilioToken=\"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"twilioToken=SK992be1adebe83f2ff461ef660e5f65d6",
				"twilio_token: SK992be1adebe83f2ff461ef660e5f65d6",
				"twilio_token: 'SK992be1adebe83f2ff461ef660e5f65d6'",
				"String twilioToken = \"SK992be1adebe83f2ff461ef660e5f65d6\";",
				"  \"twilioToken\" => \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"twilio_TOKEN ::= \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"twilioToken = \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"<twilioToken>\n    SK992be1adebe83f2ff461ef660e5f65d6\n</twilioToken>",
				"$twilioToken .= \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"twilioToken = 'SK992be1adebe83f2ff461ef660e5f65d6'",
				"twilioToken = \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"System.setProperty(\"TWILIO_TOKEN\", \"SK992be1adebe83f2ff461ef660e5f65d6\")",
				"twilio_TOKEN = \"SK992be1adebe83f2ff461ef660e5f65d6\"",
				"twilio_TOKEN :::= \"SK992be1adebe83f2ff461ef660e5f65d6\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(Twilio())
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
