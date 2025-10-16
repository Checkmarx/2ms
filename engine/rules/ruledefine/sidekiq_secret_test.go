package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSidekiqSecret(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SidekiqSecret validation",
			truePositives: []string{
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_token: '6f5557b2:9d8870b0'",
				"var BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_TOKEN = \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_TOKEN ?= \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken = 6f5557b2:9d8870b0",
				"$BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken .= \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken = '6f5557b2:9d8870b0'",
				"  \"BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken\" => \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_TOKEN :::= \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken=\"6f5557b2:9d8870b0\"",
				"{\"config.ini\": \"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_TOKEN=6f5557b2:9d8870b0\\nBACKUP_ENABLED=true\"}",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_token: \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken := \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken := `6f5557b2:9d8870b0`",
				"String BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\";",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\"",
				"System.setProperty(\"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_TOKEN\", \"6f5557b2:9d8870b0\")",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken=6f5557b2:9d8870b0",
				"{\n    \"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_token\": \"6f5557b2:9d8870b0\"\n}",
				"<BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken>\n    6f5557b2:9d8870b0\n</BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken>",
				"string BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\";",
				"var BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken string = \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_TOKEN := \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_TOKEN ::= \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COM_token: 6f5557b2:9d8870b0",
				"BUNDLE_GEMS__CONTRIBSYS__COM_token: 6f5557b2:9d8870b0",
				"$BUNDLE_GEMS__CONTRIBSYS__COMToken .= \"6f5557b2:9d8870b0\"",
				"System.setProperty(\"BUNDLE_GEMS__CONTRIBSYS__COM_TOKEN\", \"6f5557b2:9d8870b0\")",
				"BUNDLE_GEMS__CONTRIBSYS__COM_TOKEN ::= \"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\"",
				"{\"config.ini\": \"BUNDLE_GEMS__CONTRIBSYS__COM_TOKEN=6f5557b2:9d8870b0\\nBACKUP_ENABLED=true\"}",
				"string BUNDLE_GEMS__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\";",
				"var BUNDLE_GEMS__CONTRIBSYS__COMToken string = \"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COMToken := \"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COMToken = '6f5557b2:9d8870b0'",
				"BUNDLE_GEMS__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\"",
				"  \"BUNDLE_GEMS__CONTRIBSYS__COMToken\" => \"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COMToken=\"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COMToken=6f5557b2:9d8870b0",
				"{\n    \"BUNDLE_GEMS__CONTRIBSYS__COM_token\": \"6f5557b2:9d8870b0\"\n}",
				"BUNDLE_GEMS__CONTRIBSYS__COM_token: \"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COMToken := `6f5557b2:9d8870b0`",
				"String BUNDLE_GEMS__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\";",
				"BUNDLE_GEMS__CONTRIBSYS__COM_TOKEN :::= \"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COMToken = 6f5557b2:9d8870b0",
				"<BUNDLE_GEMS__CONTRIBSYS__COMToken>\n    6f5557b2:9d8870b0\n</BUNDLE_GEMS__CONTRIBSYS__COMToken>",
				"BUNDLE_GEMS__CONTRIBSYS__COM_token: '6f5557b2:9d8870b0'",
				"var BUNDLE_GEMS__CONTRIBSYS__COMToken = \"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COM_TOKEN = \"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COM_TOKEN := \"6f5557b2:9d8870b0\"",
				"BUNDLE_GEMS__CONTRIBSYS__COM_TOKEN ?= \"6f5557b2:9d8870b0\"",
				"BUNDLE_ENTERPRISE__CONTRIBSYS__COM: cafebabe:deadbeef",
				"export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef",
				"export BUNDLE_ENTERPRISE__CONTRIBSYS__COM = cafebabe:deadbeef",
				"BUNDLE_GEMS__CONTRIBSYS__COM: \"cafebabe:deadbeef\"",
				"export BUNDLE_GEMS__CONTRIBSYS__COM=\"cafebabe:deadbeef\"",
				"export BUNDLE_GEMS__CONTRIBSYS__COM = \"cafebabe:deadbeef\"",
				"export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;",
				"export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef && echo 'hello world'",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(SidekiqSecret())
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
