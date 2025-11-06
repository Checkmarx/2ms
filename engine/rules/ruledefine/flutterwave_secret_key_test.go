package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlutterwaveSecretKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "FlutterwaveSecretKey validation",
			truePositives: []string{
				"flutterwavePubKey_TOKEN :::= \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKey_TOKEN ?= \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKeyToken=\"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKeyToken = FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X",
				"{\"config.ini\": \"FLUTTERWAVEPUBKEY_TOKEN=FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\\nBACKUP_ENABLED=true\"}",
				"flutterwavePubKey_token: 'FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X'",
				"$flutterwavePubKeyToken .= \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKeyToken = \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"  \"flutterwavePubKeyToken\" => \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKeyToken = \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKeyToken=FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X",
				"string flutterwavePubKeyToken = \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\";",
				"var flutterwavePubKeyToken = \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKeyToken = 'FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X'",
				"System.setProperty(\"FLUTTERWAVEPUBKEY_TOKEN\", \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\")",
				"flutterwavePubKey_TOKEN ::= \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKey_token: FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X",
				"var flutterwavePubKeyToken string = \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKeyToken := `FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X`",
				"flutterwavePubKey_TOKEN := \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"{\n    \"flutterwavePubKey_token\": \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"\n}",
				"<flutterwavePubKeyToken>\n    FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\n</flutterwavePubKeyToken>",
				"flutterwavePubKey_token: \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"flutterwavePubKeyToken := \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
				"String flutterwavePubKeyToken = \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\";",
				"flutterwavePubKey_TOKEN = \"FLWSECK_TEST-d9009d040c7b4db9e7c5674c7aeeb3bd-X\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(FlutterwaveSecretKey())
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
