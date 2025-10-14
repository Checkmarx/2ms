package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHerokuAPIKeyV2(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "HerokuV2 validation",
			truePositives: []string{
				"herokuToken := `HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1`",
				"String herokuToken = \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\";",
				"herokuToken = \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"herokuToken=\"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"herokuToken=HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1",
				"herokuToken = HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1",
				"heroku_token: 'HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1'",
				"herokuToken := \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"$herokuToken .= \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"System.setProperty(\"HEROKU_TOKEN\", \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\")",
				"heroku_TOKEN := \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"var herokuToken = \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"  \"herokuToken\" => \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"heroku_TOKEN ?= \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"{\"config.ini\": \"HEROKU_TOKEN=HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\\nBACKUP_ENABLED=true\"}",
				"heroku_token: \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"var herokuToken string = \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"herokuToken = 'HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1'",
				"heroku_TOKEN = \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"heroku_TOKEN ::= \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"heroku_TOKEN :::= \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"herokuToken = \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"",
				"{\n    \"heroku_token\": \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\"\n}",
				"<herokuToken>\n    HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\n</herokuToken>",
				"heroku_token: HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1",
				"string herokuToken = \"HRKU-AAatc9Atjz7YYFiEux9VPaTNh1r8RH9j2Qt65qSU0EIs--5DmeHLw_7gyTs1\";",
				"const KEY = \"HRKU-AAlQ1aVoHDujJ9QsDHdHlHO0hbzhoERRSO45ZQusSYHg_____w4_hLrAym_u\"\"",
				"API_Key = \"HRKU-AAy9Ppr_HD2pPuTyIiTYInO0hbzhoERRSO93ZQusSYHgaD7_WQ07FnF7L9FX\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(HerokuV2())
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
