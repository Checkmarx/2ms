package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenshiftUserToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "OpenshiftUserToken validation",
			truePositives: []string{
				"oc_token: 'sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6'",
				"oc_token: \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"oc_TOKEN ?= \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"ocToken=\"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"<ocToken>\n    sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\n</ocToken>",
				"var ocToken = \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"ocToken = \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"System.setProperty(\"OC_TOKEN\", \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\")",
				"  \"ocToken\" => \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"oc_TOKEN :::= \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"ocToken = \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"{\"config.ini\": \"OC_TOKEN=sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\\nBACKUP_ENABLED=true\"}",
				"string ocToken = \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\";",
				"ocToken := \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"String ocToken = \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\";",
				"oc_TOKEN := \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"oc_TOKEN ::= \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"ocToken=sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6",
				"ocToken = sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6",
				"oc_token: sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6",
				"var ocToken string = \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"ocToken := `sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6`",
				"$ocToken .= \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"ocToken = 'sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6'",
				"oc_TOKEN = \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"",
				"{\n    \"oc_token\": \"sha256~4MPq9dCyZdHB-bMTDnCOSLT-77FcGmjSfaecQ_XaEM6\"\n}",
				"Authorization: Bearer sha256~kV46hPnEYhCWFnB85r5NrprAxggzgb6GOeLbgcKNsH0",
				"oc login --token=sha256~ZBMKw9VAayhdnyANaHvjJeXDiGwA7Fsr5gtLKj3-eh- ",
				"sha256~fuPXFk6800Kp8CxTzkO8zNNq6d0-NXXLCIOMaEtDiaz",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(OpenshiftUserToken())
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
