package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrafanaServiceAccountToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GrafanaServiceAccountToken validation",
			truePositives: []string{
				"grafana-service-account-token_TOKEN := \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"grafana-service-account-token_TOKEN ::= \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"grafana-service-account-token_token: glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6",
				"var grafana-service-account-tokenToken string = \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"  \"grafana-service-account-tokenToken\" => \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"grafana-service-account-token_TOKEN :::= \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"grafana-service-account-tokenToken=\"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"grafana-service-account-token_token: \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"string grafana-service-account-tokenToken = \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\";",
				"grafana-service-account-tokenToken := \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"System.setProperty(\"GRAFANA-SERVICE-ACCOUNT-TOKEN_TOKEN\", \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\")",
				"grafana-service-account-token_TOKEN ?= \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"grafana-service-account-tokenToken=glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6",
				"{\"config.ini\": \"GRAFANA-SERVICE-ACCOUNT-TOKEN_TOKEN=glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\\nBACKUP_ENABLED=true\"}",
				"grafana-service-account-token_token: 'glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6'",
				"grafana-service-account-tokenToken := `glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6`",
				"String grafana-service-account-tokenToken = \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\";",
				"var grafana-service-account-tokenToken = \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"$grafana-service-account-tokenToken .= \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"grafana-service-account-tokenToken = 'glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6'",
				"grafana-service-account-tokenToken = \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"grafana-service-account-tokenToken = glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6",
				"{\n    \"grafana-service-account-token_token\": \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"\n}",
				"<grafana-service-account-tokenToken>\n    glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\n</grafana-service-account-tokenToken>",
				"grafana-service-account-tokenToken = \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"grafana-service-account-token_TOKEN = \"glsa_fvf8iryudui5cxkvf2cvltcl2axuf614_77bc6be6\"",
				"'Authorization': 'Bearer glsa_pITqMOBIfNH2KL4PkXJqmTyQl0D9QGxF_486f63e1'",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GrafanaServiceAccountToken())
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
