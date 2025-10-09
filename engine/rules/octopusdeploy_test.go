package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOctopusDeployAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "OctopusDeployApiKey validation",
			truePositives: []string{
				"octopus_api_token = \"API-J675W2YZ2I7KAY989E5J9F1YIU\"",
				"set apikey=\"API-ZNRMR7SL6L3ATMOIK7GKJDKLPY\"",
			},
			falsePositives: []string{
				// Invalid start
				`msgstr "GSSAPI-VIRHEKAPSELOINTIMERKKIJONO."`,
				`https://sonarcloud.io/api/project_badges/measure?project=Garden-Coin_API-CalculadoraDeInvestimentos&metric=alert_status`,
				`https://fog-ringer-f42.notion.site/API-BD80F56CDC1441E6BF6011AB6D852875`,    // Invalid end
				`<iframe src="./archive/gifs/api-c99e353f761d318322c853c03e.gif"> </iframe>`, // Wrong case
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(OctopusDeployApiKey())
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
