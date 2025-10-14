package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrafanaCloudAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GrafanaCloudApiToken validation",
			truePositives: []string{
				"grafana-cloud-api-tokenToken = \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-token_TOKEN := \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-token_TOKEN ::= \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-token_TOKEN ?= \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-tokenToken=\"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"{\"config.ini\": \"GRAFANA-CLOUD-API-TOKEN_TOKEN=glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\\nBACKUP_ENABLED=true\"}",
				"string grafana-cloud-api-tokenToken = \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\";",
				"var grafana-cloud-api-tokenToken string = \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-tokenToken := \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-tokenToken = 'glc_n3wcenmqn39hxd51x8czx33l3snnq3k8'",
				"  \"grafana-cloud-api-tokenToken\" => \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-tokenToken = \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"{\n    \"grafana-cloud-api-token_token\": \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"\n}",
				"grafana-cloud-api-token_token: 'glc_n3wcenmqn39hxd51x8czx33l3snnq3k8'",
				"$grafana-cloud-api-tokenToken .= \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"System.setProperty(\"GRAFANA-CLOUD-API-TOKEN_TOKEN\", \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\")",
				"grafana-cloud-api-token_TOKEN = \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-tokenToken=glc_n3wcenmqn39hxd51x8czx33l3snnq3k8",
				"grafana-cloud-api-tokenToken = glc_n3wcenmqn39hxd51x8czx33l3snnq3k8",
				"<grafana-cloud-api-tokenToken>\n    glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\n</grafana-cloud-api-tokenToken>",
				"grafana-cloud-api-tokenToken := `glc_n3wcenmqn39hxd51x8czx33l3snnq3k8`",
				"String grafana-cloud-api-tokenToken = \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\";",
				"var grafana-cloud-api-tokenToken = \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-token_TOKEN :::= \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-token_token: glc_n3wcenmqn39hxd51x8czx33l3snnq3k8",
				"grafana-cloud-api-token_token: \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"grafana-cloud-api-token_api_token = \"glc_n3wcenmqn39hxd51x8czx33l3snnq3k8\"",
				"loki_key: glc_eyJvIjoiNzQ0NTg3IiwibiI7InN0YWlrLTQ3NTgzMC1obC13cml0ZS1oYW5kc29uJG9raSIsImsiOiI4M2w3cmdYUlBoMTUyMW1lMU023nl5UDUiLCJtIjp7IOIiOiJ1cyJ9fQ==",
			},
			falsePositives: []string{
				// Low entropy.
				`glc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`   API_KEY="glc_111111111111111111111111111111111111111111="`,
				// Invalid.
				`static void GLC_CreateLightmapTextureArray(void);
static void GLC_CreateLightmapTexturesIndividual(void);

void GLC_UploadLightmap(int textureUnit, int lightmapnum);`,
				`// Alias models
void GLC_StateBeginUnderwaterAliasModelCaustics(texture_ref base_texture, texture_ref caustics_texture)
{`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(GrafanaCloudApiToken())
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
