package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPulumiAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PulumiAPIToken validation",
			truePositives: []string{
				"pulumi-api-tokenToken = 'pul-fe651103326a96c921d61bb13f03341a30c1ef0d'",
				"pulumi-api-token_TOKEN = \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-tokenToken=\"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-tokenToken = pul-fe651103326a96c921d61bb13f03341a30c1ef0d",
				"pulumi-api-token_token: \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-token_TOKEN := \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-token_TOKEN ?= \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-tokenToken = \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-tokenToken=pul-fe651103326a96c921d61bb13f03341a30c1ef0d",
				"{\"config.ini\": \"PULUMI-API-TOKEN_TOKEN=pul-fe651103326a96c921d61bb13f03341a30c1ef0d\\nBACKUP_ENABLED=true\"}",
				"<pulumi-api-tokenToken>\n    pul-fe651103326a96c921d61bb13f03341a30c1ef0d\n</pulumi-api-tokenToken>",
				"pulumi-api-token_token: pul-fe651103326a96c921d61bb13f03341a30c1ef0d",
				"pulumi-api-tokenToken := \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-tokenToken := `pul-fe651103326a96c921d61bb13f03341a30c1ef0d`",
				"$pulumi-api-tokenToken .= \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"{\n    \"pulumi-api-token_token\": \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"\n}",
				"var pulumi-api-tokenToken string = \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"var pulumi-api-tokenToken = \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-tokenToken = \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"System.setProperty(\"PULUMI-API-TOKEN_TOKEN\", \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\")",
				"  \"pulumi-api-tokenToken\" => \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-token_TOKEN ::= \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-token_TOKEN :::= \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\"",
				"pulumi-api-token_token: 'pul-fe651103326a96c921d61bb13f03341a30c1ef0d'",
				"string pulumi-api-tokenToken = \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\";",
				"String pulumi-api-tokenToken = \"pul-fe651103326a96c921d61bb13f03341a30c1ef0d\";",
			},
			falsePositives: []string{
				`                        <img src="./assets/vipul-f0eb1acf0da84c06a50c5b2c59932001997786b176dec02bd16128ee9ea83628.png" alt="" class="w-16 h-16 rounded-full">`,
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
			rule := ConvertNewRuleToGitleaksRule(PulumiAPIToken())
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
