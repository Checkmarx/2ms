package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetlifyAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "NetlifyAccessToken validation",
			truePositives: []string{
				"netlifyToken = 'cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a'",
				"netlifyToken = \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"System.setProperty(\"NETLIFY_TOKEN\", \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\")",
				"netlifyToken = cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a",
				"{\n    \"netlify_token\": \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"\n}",
				"<netlifyToken>\n    cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\n</netlifyToken>",
				"netlify_token: 'cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a'",
				"var netlifyToken string = \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlify_TOKEN := \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlify_TOKEN ::= \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlify_TOKEN :::= \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlifyToken=\"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlifyToken=cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a",
				"netlify_token: cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a",
				"  \"netlifyToken\" => \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlify_TOKEN ?= \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlifyToken = \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"{\"config.ini\": \"NETLIFY_TOKEN=cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\\nBACKUP_ENABLED=true\"}",
				"string netlifyToken = \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\";",
				"netlifyToken := \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlifyToken := `cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a`",
				"var netlifyToken = \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"$netlifyToken .= \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlify_TOKEN = \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"netlify_token: \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\"",
				"String netlifyToken = \"cwfz3_kfof6i4wcjahpw4o3m09f4zlz=c7mj4n_a\";",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(NetlifyAccessToken())
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
