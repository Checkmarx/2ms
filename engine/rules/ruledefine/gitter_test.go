package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitterAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GitterAccessToken validation",
			truePositives: []string{
				"gitter_TOKEN ::= \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"gitter_TOKEN ?= \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"gitterToken = etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5",
				"{\n    \"gitter_token\": \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"\n}",
				"{\"config.ini\": \"GITTER_TOKEN=etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\\nBACKUP_ENABLED=true\"}",
				"gitter_token: 'etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5'",
				"var gitterToken = \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"$gitterToken .= \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"gitterToken = 'etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5'",
				"System.setProperty(\"GITTER_TOKEN\", \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\")",
				"gitterToken=\"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"<gitterToken>\n    etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\n</gitterToken>",

				"gitter_token: \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"string gitterToken = \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\";",
				"String gitterToken = \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\";",
				"gitter_TOKEN = \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"gitter_TOKEN :::= \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"gitterToken=etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5",
				"gitterToken := \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"gitterToken = \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"  \"gitterToken\" => \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"gitterToken = \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"gitter_token: etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5",
				"var gitterToken string = \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
				"gitterToken := `etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5`",
				"gitter_TOKEN := \"etbctr064344ap0d228ihvo9a_2mnfhk5hppx_l5\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GitterAccessToken())
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
