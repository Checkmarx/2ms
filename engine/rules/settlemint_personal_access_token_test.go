package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
)

func TestSettlemintPersonalAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SettlemintPersonalAccessToken validation",
			truePositives: []string{
				"settlemintToken_TOKEN ::= \"sm_pat_2dzyue1ub5v651iy\"",
				"settlemintTokenToken = \"sm_pat_2dzyue1ub5v651iy\"",
				"{\n    \"settlemintToken_token\": \"sm_pat_2dzyue1ub5v651iy\"\n}",
				"{\"config.ini\": \"SETTLEMINTTOKEN_TOKEN=sm_pat_2dzyue1ub5v651iy\\nBACKUP_ENABLED=true\"}",
				"settlemintToken_token: sm_pat_2dzyue1ub5v651iy",
				"settlemintToken_token: 'sm_pat_2dzyue1ub5v651iy'",
				"string settlemintTokenToken = \"sm_pat_2dzyue1ub5v651iy\";",
				"settlemintTokenToken := `sm_pat_2dzyue1ub5v651iy`",
				"settlemintToken_TOKEN = \"sm_pat_2dzyue1ub5v651iy\"",
				"settlemintTokenToken=\"sm_pat_2dzyue1ub5v651iy\"",
				"settlemintTokenToken = sm_pat_2dzyue1ub5v651iy",
				"<settlemintTokenToken>\n    sm_pat_2dzyue1ub5v651iy\n</settlemintTokenToken>",
				"settlemintToken_token: \"sm_pat_2dzyue1ub5v651iy\"",
				"settlemintTokenToken = 'sm_pat_2dzyue1ub5v651iy'",
				"settlemintToken_TOKEN :::= \"sm_pat_2dzyue1ub5v651iy\"",
				"settlemintToken_TOKEN ?= \"sm_pat_2dzyue1ub5v651iy\"",
				"String settlemintTokenToken = \"sm_pat_2dzyue1ub5v651iy\";",
				"var settlemintTokenToken = \"sm_pat_2dzyue1ub5v651iy\"",
				"System.setProperty(\"SETTLEMINTTOKEN_TOKEN\", \"sm_pat_2dzyue1ub5v651iy\")",
				"  \"settlemintTokenToken\" => \"sm_pat_2dzyue1ub5v651iy\"",
				"settlemintTokenToken=sm_pat_2dzyue1ub5v651iy",
				"var settlemintTokenToken string = \"sm_pat_2dzyue1ub5v651iy\"",
				"settlemintTokenToken := \"sm_pat_2dzyue1ub5v651iy\"",
				"$settlemintTokenToken .= \"sm_pat_2dzyue1ub5v651iy\"",
				"settlemintTokenToken = \"sm_pat_2dzyue1ub5v651iy\"",
				"settlemintToken_TOKEN := \"sm_pat_2dzyue1ub5v651iy\"",
			},
			falsePositives: []string{
				"nonMatchingToken := \"" + secrets.NewSecret(AlphaNumeric("16")) + "\"",
				"nonMatchingToken := \"sm_pat_" + secrets.NewSecret(AlphaNumeric("10")) + "\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(SettlemintPersonalAccessToken())
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
