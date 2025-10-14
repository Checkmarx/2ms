package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlanetScalePassword(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PlanetScalePassword validation",
			truePositives: []string{
				"planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"<planetScaleToken>\n    pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\n</planetScaleToken>",
				"planetScale_token: 'pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj'",
				"string planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\";",
				"planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"System.setProperty(\"PLANETSCALE_TOKEN\", \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\")",
				"  \"planetScaleToken\" => \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"planetScaleToken=pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj",
				"planetScale_token: \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"var planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"planetScale_TOKEN := \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"planetScale_TOKEN ::= \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"{\n    \"planetScale_token\": \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"\n}",
				"planetScale_token: pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj",
				"var planetScaleToken string = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"String planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\";",
				"$planetScaleToken .= \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"planetScale_TOKEN = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"planetScale_TOKEN ?= \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"planetScaleToken=\"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"planetScaleToken = pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj",
				"{\"config.ini\": \"PLANETSCALE_TOKEN=pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\\nBACKUP_ENABLED=true\"}",
				"planetScaleToken := \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"planetScaleToken := `pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj`",
				"planetScaleToken = 'pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj'",
				"planetScale_TOKEN :::= \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj\"",
				"planetScale_TOKEN := \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"planetScale_token: 'pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn'",
				"planetScale_token: \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"planetScaleToken := `pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn`",
				"$planetScaleToken .= \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"  \"planetScaleToken\" => \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"planetScale_TOKEN ::= \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"{\"config.ini\": \"PLANETSCALE_TOKEN=pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\\nBACKUP_ENABLED=true\"}",
				"planetScaleToken := \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"System.setProperty(\"PLANETSCALE_TOKEN\", \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\")",
				"planetScale_TOKEN = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"planetScaleToken=\"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"{\n    \"planetScale_token\": \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"\n}",
				"var planetScaleToken string = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"String planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\";",
				"var planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"planetScale_TOKEN :::= \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"planetScale_TOKEN ?= \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"planetScaleToken=pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn",
				"planetScaleToken = pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn",
				"<planetScaleToken>\n    pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\n</planetScaleToken>",
				"planetScale_token: pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn",
				"string planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\";",
				"planetScaleToken = 'pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn'",
				"planetScaleToken = \"pscale_pw_p3p5xaypd-h9u26h3qqv72tqhxwi1rzj_zy99iqv2fn\"",
				"$planetScaleToken .= \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScaleToken = 'pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow'",
				"planetScaleToken = \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"System.setProperty(\"PLANETSCALE_TOKEN\", \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\")",
				"planetScale_TOKEN :::= \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScale_TOKEN ?= \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScale_token: \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"string planetScaleToken = \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\";",
				"var planetScaleToken string = \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScaleToken := \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScale_TOKEN := \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScale_TOKEN ::= \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScaleToken=pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow",
				"planetScale_token: pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow",
				"String planetScaleToken = \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\";",
				"  \"planetScaleToken\" => \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScale_TOKEN = \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScaleToken=\"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScaleToken = \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScaleToken = pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow",
				"{\n    \"planetScale_token\": \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"\n}",
				"{\"config.ini\": \"PLANETSCALE_TOKEN=pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\\nBACKUP_ENABLED=true\"}",
				"<planetScaleToken>\n    pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\n</planetScaleToken>",
				"planetScaleToken := `pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow`",
				"var planetScaleToken = \"pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow\"",
				"planetScale_token: 'pscale_pw_4ednciy3i0isfcc-hkg81k8s-1qltkoalwox4q-expuiswg7roazjdq=x9fzv3ow'",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(PlanetScalePassword())
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
