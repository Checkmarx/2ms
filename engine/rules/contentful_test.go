package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContentfulDeliveryApiToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ContentfulDeliveryApiToken validation",
			truePositives: []string{
				"$contentfulToken .= \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentfulToken=\"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentful_token: \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentfulToken := \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"String contentfulToken = \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\";",
				"contentfulToken = \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"  \"contentfulToken\" => \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentful_TOKEN = \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentful_TOKEN := \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentfulToken = \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"var contentfulToken = \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentfulToken = '3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig'",
				"contentful_TOKEN :::= \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentfulToken = 3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig",
				"var contentfulToken string = \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentfulToken := `3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig`",
				"System.setProperty(\"CONTENTFUL_TOKEN\", \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\")",
				"contentful_TOKEN ::= \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentful_TOKEN ?= \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"",
				"contentfulToken=3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig",
				"{\n    \"contentful_token\": \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\"\n}",
				"{\"config.ini\": \"CONTENTFUL_TOKEN=3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\\nBACKUP_ENABLED=true\"}",
				"<contentfulToken>\n    3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\n</contentfulToken>",
				"contentful_token: 3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig",
				"contentful_token: '3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig'",
				"string contentfulToken = \"3erlcg6cvoqdumi6x752piedfeyin13dlz9wc6hj1ig\";",
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
			rule := ConvertNewRuleToGitleaksRule(ContentfulDeliveryApiToken())
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
