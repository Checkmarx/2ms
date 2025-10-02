package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
)

func TestSettlemintApplicationAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SettlemintApplicationAccessToken validation",
			truePositives: []string{
				"settlemintTokenToken=sm_aat_js745fpgq781pr1l",
				"settlemintToken_token: 'sm_aat_js745fpgq781pr1l'",
				"settlemintToken_token: \"sm_aat_js745fpgq781pr1l\"",
				"settlemintTokenToken := `sm_aat_js745fpgq781pr1l`",
				"var settlemintTokenToken = \"sm_aat_js745fpgq781pr1l\"",
				"System.setProperty(\"SETTLEMINTTOKEN_TOKEN\", \"sm_aat_js745fpgq781pr1l\")",
				"  \"settlemintTokenToken\" => \"sm_aat_js745fpgq781pr1l\"",
				"settlemintTokenToken = sm_aat_js745fpgq781pr1l",
				"{\n    \"settlemintToken_token\": \"sm_aat_js745fpgq781pr1l\"\n}",
				"settlemintToken_TOKEN := \"sm_aat_js745fpgq781pr1l\"",
				"settlemintToken_TOKEN :::= \"sm_aat_js745fpgq781pr1l\"",
				"settlemintTokenToken=\"sm_aat_js745fpgq781pr1l\"",
				"var settlemintTokenToken string = \"sm_aat_js745fpgq781pr1l\"",
				"$settlemintTokenToken .= \"sm_aat_js745fpgq781pr1l\"",
				"settlemintToken_TOKEN = \"sm_aat_js745fpgq781pr1l\"",
				"settlemintToken_TOKEN ::= \"sm_aat_js745fpgq781pr1l\"",
				"settlemintToken_TOKEN ?= \"sm_aat_js745fpgq781pr1l\"",
				"{\"config.ini\": \"SETTLEMINTTOKEN_TOKEN=sm_aat_js745fpgq781pr1l\\nBACKUP_ENABLED=true\"}",
				"<settlemintTokenToken>\n    sm_aat_js745fpgq781pr1l\n</settlemintTokenToken>",
				"settlemintToken_token: sm_aat_js745fpgq781pr1l",
				"string settlemintTokenToken = \"sm_aat_js745fpgq781pr1l\";",
				"settlemintTokenToken := \"sm_aat_js745fpgq781pr1l\"",
				"String settlemintTokenToken = \"sm_aat_js745fpgq781pr1l\";",
				"settlemintTokenToken = 'sm_aat_js745fpgq781pr1l'",
				"settlemintTokenToken = \"sm_aat_js745fpgq781pr1l\"",
				"settlemintTokenToken = \"sm_aat_js745fpgq781pr1l\"",
			},
			falsePositives: []string{
				"nonMatchingToken := \"" + secrets.NewSecret(utils.AlphaNumeric("16")) + "\"",
				"nonMatchingToken := \"sm_aat_" + secrets.NewSecret(utils.AlphaNumeric("10")) + "\"",
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
			rule := ConvertNewRuleToGitleaksRule(SettlemintApplicationAccessToken())
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
