package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJfrogIdentityToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "JFrogIdentityToken validation",
			truePositives: []string{
				"jfrogToken=\"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"jfrogToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"jfrogToken=itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"jfrogToken = itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"{\"config.ini\": \"JFROG_TOKEN=itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\\nBACKUP_ENABLED=true\"}",
				"jfrog_token: 'itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp'",
				"jfrog_token: \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"$jfrogToken .= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"jfrogToken := `itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp`",
				"String jfrogToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\";",
				"var jfrogToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"jfrogToken = 'itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp'",
				"System.setProperty(\"JFROG_TOKEN\", \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\")",
				"jfrog_TOKEN ::= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"jfrog_TOKEN :::= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"jfrog_TOKEN ?= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"{\n    \"jfrog_token\": \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"\n}",
				"<jfrogToken>\n    itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\n</jfrogToken>",
				"jfrog_token: itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"var jfrogToken string = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"jfrog_TOKEN = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"jfrog_TOKEN := \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"string jfrogToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\";",
				"jfrogToken := \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"jfrogToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"  \"jfrogToken\" => \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"var artifactoryToken string = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"String artifactoryToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\";",
				"artifactoryToken = 'itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp'",
				"artifactory_TOKEN :::= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",

				"artifactory_TOKEN ?= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"{\"config.ini\": \"ARTIFACTORY_TOKEN=itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\\nBACKUP_ENABLED=true\"}",
				"artifactory_token: 'itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp'",
				"string artifactoryToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\";",
				"artifactoryToken := \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"$artifactoryToken .= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"artifactoryToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"System.setProperty(\"ARTIFACTORY_TOKEN\", \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\")",
				"artifactory_TOKEN ::= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"artifactoryToken=\"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"artifactoryToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"{\n    \"artifactory_token\": \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"\n}",
				"artifactory_token: itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"artifactoryToken := `itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp`",
				"var artifactoryToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",

				"artifactory_TOKEN = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"artifactory_TOKEN := \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"artifactoryToken = itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"  \"artifactoryToken\" => \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"artifactoryToken=itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"<artifactoryToken>\n    itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\n</artifactoryToken>",
				"artifactory_token: \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"bintrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"bintrayToken = itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"bintray_token: itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"var bintrayToken string = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"$bintrayToken .= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"bintray_TOKEN :::= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"bintray_TOKEN ?= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"{\n    \"bintray_token\": \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"\n}",
				"bintray_token: 'itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp'",
				"bintray_token: \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"var bintrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"System.setProperty(\"BINTRAY_TOKEN\", \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\")",
				"bintray_TOKEN = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"bintrayToken=\"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"bintrayToken=itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"<bintrayToken>\n    itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\n</bintrayToken>",
				"string bintrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\";",

				"bintrayToken := \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"bintrayToken := `itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp`",
				"bintrayToken = 'itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp'",
				"bintrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"{\"config.ini\": \"BINTRAY_TOKEN=itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\\nBACKUP_ENABLED=true\"}",
				"String bintrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\";",

				"  \"bintrayToken\" => \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"bintray_TOKEN := \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"bintray_TOKEN ::= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"var xrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"$xrayToken .= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xray_TOKEN := \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xray_TOKEN ?= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xrayToken=itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"<xrayToken>\n    itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\n</xrayToken>",
				"xray_token: 'itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp'",
				"var xrayToken string = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",

				"xrayToken := `itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp`",
				"String xrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\";",
				"xrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xrayToken = itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"{\n    \"xray_token\": \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"\n}",
				"{\"config.ini\": \"XRAY_TOKEN=itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\\nBACKUP_ENABLED=true\"}",
				"string xrayToken = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\";",
				"xrayToken = 'itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp'",
				"System.setProperty(\"XRAY_TOKEN\", \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\")",
				"xray_TOKEN = \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xray_TOKEN ::= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xrayToken=\"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xray_token: itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp",
				"xray_token: \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"  \"xrayToken\" => \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xray_TOKEN :::= \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"xrayToken := \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
				"\"artifactory\", \"itgqec2vkrwgtutuj4qh8lal3v1plqdzvbvlvndm714ucg2pop4z1lhxa96n6zlp\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(JFrogIdentityToken())
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
