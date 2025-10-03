package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRubyGemsAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "RubyGemsAPIToken validation",
			truePositives: []string{

				"rubygemsAPIToken_TOKEN ::= \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"rubygemsAPITokenToken = \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"{\n    \"rubygemsAPIToken_token\": \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"\n}",
				"rubygemsAPIToken_token: rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82",
				"rubygemsAPIToken_token: 'rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82'",
				"string rubygemsAPITokenToken = \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\";",
				"rubygemsAPITokenToken = 'rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82'",
				"rubygemsAPIToken_TOKEN = \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"rubygemsAPITokenToken = rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82",
				"<rubygemsAPITokenToken>\n    rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\n</rubygemsAPITokenToken>",
				"var rubygemsAPITokenToken string = \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"rubygemsAPITokenToken := \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"String rubygemsAPITokenToken = \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\";",
				"rubygemsAPITokenToken = \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"rubygemsAPIToken_TOKEN :::= \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"rubygemsAPIToken_TOKEN ?= \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"rubygemsAPITokenToken=\"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"{\"config.ini\": \"RUBYGEMSAPITOKEN_TOKEN=rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\\nBACKUP_ENABLED=true\"}",
				"rubygemsAPITokenToken := `rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82`",
				"var rubygemsAPITokenToken = \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"System.setProperty(\"RUBYGEMSAPITOKEN_TOKEN\", \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\")",
				"  \"rubygemsAPITokenToken\" => \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"rubygemsAPITokenToken=rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82",
				"rubygemsAPIToken_token: \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"$rubygemsAPITokenToken .= \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
				"rubygemsAPIToken_TOKEN := \"rubygems_8c855e7195184546f920366d523d88530ead57c5c618be82\"",
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
			rule := ConvertNewRuleToGitleaksRule(RubyGemsAPIToken())
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
