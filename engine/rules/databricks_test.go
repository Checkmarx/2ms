package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDatabricksApiToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DatabricksApiToken validation",
			truePositives: []string{
				"System.setProperty(\"DATABRICKS_TOKEN\", \"dapi4d332ee2c7d03f21ad34dc322982290c\")",
				"databricksToken=dapi4d332ee2c7d03f21ad34dc322982290c",
				"databricks_token: dapi4d332ee2c7d03f21ad34dc322982290c",
				"databricks_token: \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"var databricksToken string = \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"String databricksToken = \"dapi4d332ee2c7d03f21ad34dc322982290c\";",
				"  \"databricksToken\" => \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricks_TOKEN :::= \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricksToken = dapi4d332ee2c7d03f21ad34dc322982290c",
				"{\n    \"databricks_token\": \"dapi4d332ee2c7d03f21ad34dc322982290c\"\n}",
				"databricksToken := \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricksToken := `dapi4d332ee2c7d03f21ad34dc322982290c`",
				"var databricksToken = \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricks_TOKEN := \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricks_TOKEN ::= \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricks_TOKEN ?= \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricks_token: 'dapi4d332ee2c7d03f21ad34dc322982290c'",
				"string databricksToken = \"dapi4d332ee2c7d03f21ad34dc322982290c\";",
				"databricks_TOKEN = \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricksToken=\"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricksToken = \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"{\"config.ini\": \"DATABRICKS_TOKEN=dapi4d332ee2c7d03f21ad34dc322982290c\\nBACKUP_ENABLED=true\"}",
				"<databricksToken>\n    dapi4d332ee2c7d03f21ad34dc322982290c\n</databricksToken>",
				"$databricksToken .= \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
				"databricksToken = 'dapi4d332ee2c7d03f21ad34dc322982290c'",
				"databricksToken = \"dapi4d332ee2c7d03f21ad34dc322982290c\"",
			},
			falsePositives: []string{
				`DATABRICKS_TOKEN=dapi123456789012345678a9bc01234defg5`,
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
			rule := ConvertNewRuleToGitleaksRule(DatabricksApiToken())
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
