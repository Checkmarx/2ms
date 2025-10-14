package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScalingoAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ScalingoAPIToken validation",
			truePositives: []string{
				"scalingoToken = \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"scalingoToken=tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo",
				"scalingoToken = tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo",
				"<scalingoToken>\n    tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\n</scalingoToken>",
				"scalingo_token: \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"var scalingoToken string = \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"String scalingoToken = \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\";",
				"scalingoToken = \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"{\n    \"scalingo_token\": \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"\n}",
				"{\"config.ini\": \"SCALINGO_TOKEN=tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\\nBACKUP_ENABLED=true\"}",
				"scalingo_token: 'tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo'",
				"scalingoToken := `tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo`",
				"scalingoToken = 'tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo'",
				"scalingo_TOKEN :::= \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"scalingoToken=\"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"scalingo_token: tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo",
				"$scalingoToken .= \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"  \"scalingoToken\" => \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"scalingo_TOKEN = \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"scalingo_TOKEN := \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"scalingo_TOKEN ?= \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"string scalingoToken = \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\";",
				"scalingoToken := \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"var scalingoToken = \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
				"System.setProperty(\"SCALINGO_TOKEN\", \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\")",
				"scalingo_TOKEN ::= \"tk-us-clf9i7daokrtew-jadn0nekihkbry46zwxrsm_joxgl1s6jo\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(ScalingoAPIToken())
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
