package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
)

func TestSettlemintServiceAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SettlemintServiceAccessToken validation",
			truePositives: []string{
				"settlemintTokenToken=sm_sat_r48u9go4gezocjnx",
				"String settlemintTokenToken = \"sm_sat_r48u9go4gezocjnx\";",
				"settlemintToken_TOKEN = \"sm_sat_r48u9go4gezocjnx\"",
				"settlemintToken_TOKEN :::= \"sm_sat_r48u9go4gezocjnx\"",
				"settlemintToken_TOKEN ?= \"sm_sat_r48u9go4gezocjnx\"",
				"settlemintTokenToken=\"sm_sat_r48u9go4gezocjnx\"",
				"{\n    \"settlemintToken_token\": \"sm_sat_r48u9go4gezocjnx\"\n}",
				"settlemintToken_token: sm_sat_r48u9go4gezocjnx",
				"settlemintToken_token: 'sm_sat_r48u9go4gezocjnx'",
				"var settlemintTokenToken string = \"sm_sat_r48u9go4gezocjnx\"",
				"settlemintTokenToken = 'sm_sat_r48u9go4gezocjnx'",
				"System.setProperty(\"SETTLEMINTTOKEN_TOKEN\", \"sm_sat_r48u9go4gezocjnx\")",
				"  \"settlemintTokenToken\" => \"sm_sat_r48u9go4gezocjnx\"",
				"{\"config.ini\": \"SETTLEMINTTOKEN_TOKEN=sm_sat_r48u9go4gezocjnx\\nBACKUP_ENABLED=true\"}",
				"<settlemintTokenToken>\n    sm_sat_r48u9go4gezocjnx\n</settlemintTokenToken>",
				"settlemintTokenToken := \"sm_sat_r48u9go4gezocjnx\"",
				"var settlemintTokenToken = \"sm_sat_r48u9go4gezocjnx\"",
				"$settlemintTokenToken .= \"sm_sat_r48u9go4gezocjnx\"",
				"settlemintTokenToken = \"sm_sat_r48u9go4gezocjnx\"",
				"settlemintToken_TOKEN := \"sm_sat_r48u9go4gezocjnx\"",
				"settlemintToken_TOKEN ::= \"sm_sat_r48u9go4gezocjnx\"",
				"settlemintTokenToken = \"sm_sat_r48u9go4gezocjnx\"",
				"settlemintTokenToken = sm_sat_r48u9go4gezocjnx",
				"settlemintToken_token: \"sm_sat_r48u9go4gezocjnx\"",
				"string settlemintTokenToken = \"sm_sat_r48u9go4gezocjnx\";",
				"settlemintTokenToken := `sm_sat_r48u9go4gezocjnx`",
			},
			falsePositives: []string{
				"nonMatchingToken := \"" + secrets.NewSecret(utils.AlphaNumeric("16")) + "\"",
				"nonMatchingToken := \"sm_sat_" + secrets.NewSecret(utils.AlphaNumeric("10")) + "\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(SettlemintServiceAccessToken())
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
