package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHerokuAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Heroku validation",
			truePositives: []string{
				"herokuToken = \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"  \"herokuToken\" => \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"heroku_TOKEN = \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"heroku_TOKEN :::= \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"{\n    \"heroku_token\": \"af94302f-4563-5462-bf92-1cfff796ad57\"\n}",
				"String herokuToken = \"af94302f-4563-5462-bf92-1cfff796ad57\";",
				"var herokuToken = \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"$herokuToken .= \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"System.setProperty(\"HEROKU_TOKEN\", \"af94302f-4563-5462-bf92-1cfff796ad57\")",
				"heroku_TOKEN ?= \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"heroku_token: 'af94302f-4563-5462-bf92-1cfff796ad57'",
				"herokuToken := `af94302f-4563-5462-bf92-1cfff796ad57`",
				"heroku_TOKEN := \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"heroku_TOKEN ::= \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"herokuToken=\"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"herokuToken = \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"herokuToken=af94302f-4563-5462-bf92-1cfff796ad57",
				"herokuToken = af94302f-4563-5462-bf92-1cfff796ad57",
				"<herokuToken>\n    af94302f-4563-5462-bf92-1cfff796ad57\n</herokuToken>",
				"heroku_token: \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"string herokuToken = \"af94302f-4563-5462-bf92-1cfff796ad57\";",
				"var herokuToken string = \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"{\"config.ini\": \"HEROKU_TOKEN=af94302f-4563-5462-bf92-1cfff796ad57\\nBACKUP_ENABLED=true\"}",
				"heroku_token: af94302f-4563-5462-bf92-1cfff796ad57",
				"herokuToken := \"af94302f-4563-5462-bf92-1cfff796ad57\"",
				"herokuToken = 'af94302f-4563-5462-bf92-1cfff796ad57'",
				"const HEROKU_KEY = \"12345678-ABCD-ABCD-ABCD-1234567890AB\"",
				"heroku_api_key = \"832d2129-a846-4e27-99f4-7004b6ad53ef\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(Heroku())
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
