package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlanetScaleOAuthToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PlanetScaleOAuthToken validation",
			truePositives: []string{
				"$planetScaleToken .= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"planetScale_TOKEN :::= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"planetScaleToken=pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695",
				"planetScaleToken = pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695",
				"{\"config.ini\": \"PLANETSCALE_TOKEN=pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\\nBACKUP_ENABLED=true\"}",
				"<planetScaleToken>\n    pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\n</planetScaleToken>",
				"planetScaleToken := \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"planetScaleToken := `pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695`",
				"var planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"planetScale_TOKEN = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"{\n    \"planetScale_token\": \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"\n}",
				"planetScale_token: pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695",
				"planetScale_token: 'pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695'",
				"planetScaleToken = 'pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695'",
				"planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"System.setProperty(\"PLANETSCALE_TOKEN\", \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\")",
				"planetScale_TOKEN ::= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"planetScaleToken=\"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"planetScale_token: \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"string planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\";",
				"var planetScaleToken string = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"String planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\";",
				"  \"planetScaleToken\" => \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"planetScale_TOKEN := \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"planetScale_TOKEN ?= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695\"",
				"  \"planetScaleToken\" => \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScale_TOKEN ::= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScaleToken = pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v",
				"{\n    \"planetScale_token\": \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"\n}",
				"planetScale_token: pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v",
				"var planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"$planetScaleToken .= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScale_TOKEN := \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScale_TOKEN :::= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScale_TOKEN ?= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"string planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\";",
				"planetScaleToken := \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"String planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\";",
				"planetScaleToken = 'pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v'",
				"System.setProperty(\"PLANETSCALE_TOKEN\", \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\")",
				"planetScale_TOKEN = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScaleToken=\"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScaleToken=pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v",
				"{\"config.ini\": \"PLANETSCALE_TOKEN=pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\\nBACKUP_ENABLED=true\"}",
				"planetScale_token: 'pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v'",
				"planetScale_token: \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"<planetScaleToken>\n    pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\n</planetScaleToken>",
				"var planetScaleToken string = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v\"",
				"planetScaleToken := `pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7v`",
				"planetScale_TOKEN = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"planetScale_TOKEN ::= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"planetScale_TOKEN :::= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"planetScaleToken=\"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"planetScale_token: \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"string planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\";",
				"planetScaleToken := `pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp`",
				"var planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"$planetScaleToken .= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"planetScaleToken = 'pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp'",
				"planetScaleToken=pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp",
				"planetScaleToken = pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp",
				"{\n    \"planetScale_token\": \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"\n}",
				"{\"config.ini\": \"PLANETSCALE_TOKEN=pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\\nBACKUP_ENABLED=true\"}",
				"planetScale_token: 'pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp'",
				"String planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\";",
				"planetScaleToken = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"  \"planetScaleToken\" => \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"<planetScaleToken>\n    pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\n</planetScaleToken>",
				"planetScale_token: pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp",
				"System.setProperty(\"PLANETSCALE_TOKEN\", \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\")",
				"planetScale_TOKEN := \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"planetScale_TOKEN ?= \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"var planetScaleToken string = \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
				"planetScaleToken := \"pscale_oauth_drn9jbl3af19bcxsm4-kql561wh3d695urks=o-ye7vmwj9eqwja0hls55a666pp\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(PlanetScaleOAuthToken())
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
