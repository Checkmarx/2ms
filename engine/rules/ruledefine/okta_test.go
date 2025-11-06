package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOktaAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "OktaAccessToken validation",
			truePositives: []string{
				"var oktaToken = \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"oktaToken = '00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt'",
				"  \"oktaToken\" => \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"okta_TOKEN := \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"oktaToken=\"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"{\n    \"okta_token\": \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"\n}",
				"okta_token: 00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt",
				"string oktaToken = \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\";",
				"$oktaToken .= \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"oktaToken = \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"okta_TOKEN :::= \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"{\"config.ini\": \"OKTA_TOKEN=00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\\nBACKUP_ENABLED=true\"}",
				"okta_token: '00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt'",
				"okta_token: \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"oktaToken := `00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt`",
				"okta_TOKEN ::= \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"okta_TOKEN ?= \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"oktaToken = 00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt",
				"oktaToken := \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"String oktaToken = \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\";",
				"System.setProperty(\"OKTA_TOKEN\", \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\")",
				"okta_TOKEN = \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"oktaToken = \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"oktaToken=00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt",
				"<oktaToken>\n    00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\n</oktaToken>",
				"var oktaToken string = \"00MFNvT0aO0JRCLdy9Ue=EhjTnRkDPjvQmmZhV5xQt\"",
				"\"oktaApiToken\": \"00ebObu4zSNkyc6dimLvUwq4KpTEop-PCEnnfSTpD3\",",
				"\t\t\tvar OktaApiToken = \"00fWkOjwwL9xiFd-Vfgm_ePATIRxVj852Iblbb1DS_\";",
			},
			falsePositives: []string{
				`oktaKey = 00000000000000000000000000000000000TUVWXYZ`,   // low entropy
				`rookTable = 0023452Lllk2KqjLBvaxANWEgTd7bqjsxjo8aZj0wd`, // wrong case
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(OktaAccessToken())
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
