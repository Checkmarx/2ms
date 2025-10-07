package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlgolia(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Algolia validation",
			truePositives: []string{
				"string algoliaToken = \"b28323d7b76c4978e305bcbb5149cd88\";",
				"algoliaToken := `b28323d7b76c4978e305bcbb5149cd88`",
				"String algoliaToken = \"b28323d7b76c4978e305bcbb5149cd88\";",
				"var algoliaToken = \"b28323d7b76c4978e305bcbb5149cd88\"",
				"System.setProperty(\"ALGOLIA_TOKEN\", \"b28323d7b76c4978e305bcbb5149cd88\")",
				"algolia_TOKEN = \"b28323d7b76c4978e305bcbb5149cd88\"",
				"algolia_TOKEN ::= \"b28323d7b76c4978e305bcbb5149cd88\"",
				"algoliaToken=\"b28323d7b76c4978e305bcbb5149cd88\"",
				"algoliaToken=b28323d7b76c4978e305bcbb5149cd88",
				"algoliaToken = b28323d7b76c4978e305bcbb5149cd88",
				"{\n    \"algolia_token\": \"b28323d7b76c4978e305bcbb5149cd88\"\n}",
				"algolia_token: 'b28323d7b76c4978e305bcbb5149cd88'",
				"var algoliaToken string = \"b28323d7b76c4978e305bcbb5149cd88\"",
				"algoliaToken := \"b28323d7b76c4978e305bcbb5149cd88\"",
				"algoliaToken = 'b28323d7b76c4978e305bcbb5149cd88'",
				"algoliaToken = \"b28323d7b76c4978e305bcbb5149cd88\"",
				"{\"config.ini\": \"ALGOLIA_TOKEN=b28323d7b76c4978e305bcbb5149cd88\\nBACKUP_ENABLED=true\"}",
				"<algoliaToken>\n    b28323d7b76c4978e305bcbb5149cd88\n</algoliaToken>",
				"$algoliaToken .= \"b28323d7b76c4978e305bcbb5149cd88\"",
				"algoliaToken = \"b28323d7b76c4978e305bcbb5149cd88\"",
				"algolia_TOKEN := \"b28323d7b76c4978e305bcbb5149cd88\"",
				"algolia_TOKEN ?= \"b28323d7b76c4978e305bcbb5149cd88\"",
				"algolia_token: b28323d7b76c4978e305bcbb5149cd88",
				"algolia_token: \"b28323d7b76c4978e305bcbb5149cd88\"",
				"  \"algoliaToken\" => \"b28323d7b76c4978e305bcbb5149cd88\"",
				"algolia_TOKEN :::= \"b28323d7b76c4978e305bcbb5149cd88\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(AlgoliaApiKey())
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
