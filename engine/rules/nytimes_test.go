package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNytimesAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "NytimesAccessToken validation",
			truePositives: []string{
				"<nytimesToken>\n    v7z0zp85ewsqa81di5pugik3v3fawdj9\n</nytimesToken>",
				"nytimes_token: v7z0zp85ewsqa81di5pugik3v3fawdj9",
				"string nytimesToken = \"v7z0zp85ewsqa81di5pugik3v3fawdj9\";",
				"nytimesToken := \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"$nytimesToken .= \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"nytimesToken = 'v7z0zp85ewsqa81di5pugik3v3fawdj9'",
				"nytimesToken = \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"nytimes_TOKEN = \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"nytimesToken = v7z0zp85ewsqa81di5pugik3v3fawdj9",
				"nytimes_token: 'v7z0zp85ewsqa81di5pugik3v3fawdj9'",
				"System.setProperty(\"NYTIMES_TOKEN\", \"v7z0zp85ewsqa81di5pugik3v3fawdj9\")",
				"nytimes_TOKEN :::= \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"nytimes_TOKEN ?= \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"nytimesToken=\"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"nytimesToken = \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"nytimesToken=v7z0zp85ewsqa81di5pugik3v3fawdj9",
				"var nytimesToken string = \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"nytimesToken := `v7z0zp85ewsqa81di5pugik3v3fawdj9`",
				"String nytimesToken = \"v7z0zp85ewsqa81di5pugik3v3fawdj9\";",
				"nytimes_TOKEN := \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"nytimes_TOKEN ::= \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"{\n    \"nytimes_token\": \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"\n}",
				"{\"config.ini\": \"NYTIMES_TOKEN=v7z0zp85ewsqa81di5pugik3v3fawdj9\\nBACKUP_ENABLED=true\"}",
				"nytimes_token: \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"var nytimesToken = \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
				"  \"nytimesToken\" => \"v7z0zp85ewsqa81di5pugik3v3fawdj9\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(NytimesAccessToken())
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
