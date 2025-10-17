package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDatadogAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "DatadogtokenAccessToken validation",
			truePositives: []string{
				"datadogToken = \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"<datadogToken>\n    ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\n</datadogToken>",
				"datadogToken := \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadogToken := `ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw`",
				"String datadogToken = \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\";",
				"$datadogToken .= \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadog_TOKEN ::= \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadog_TOKEN :::= \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"{\n    \"datadog_token\": \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"\n}",
				"{\"config.ini\": \"DATADOG_TOKEN=ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\\nBACKUP_ENABLED=true\"}",
				"datadog_token: 'ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw'",
				"datadog_token: \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"  \"datadogToken\" => \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadog_TOKEN = \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadog_TOKEN ?= \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadog_token: ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw",
				"var datadogToken string = \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadogToken = 'ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw'",
				"System.setProperty(\"DATADOG_TOKEN\", \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\")",
				"datadog_TOKEN := \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadogToken=\"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadogToken=ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw",
				"datadogToken = ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw",
				"string datadogToken = \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\";",
				"var datadogToken = \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
				"datadogToken = \"ayen4o4yr80wpo1bgnyadugz46eqq3ik4287h3zw\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(DatadogtokenAccessToken())
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
