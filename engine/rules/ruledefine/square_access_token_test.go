package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSquareAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SquareAccessToken validation",
			truePositives: []string{
				"squareToken=EAAAb0fr7dls9W2vh4ESpWsHfN",
				"{\"config.ini\": \"SQUARE_TOKEN=EAAAb0fr7dls9W2vh4ESpWsHfN\\nBACKUP_ENABLED=true\"}",
				"square_token: 'EAAAb0fr7dls9W2vh4ESpWsHfN'",
				"squareToken := `EAAAb0fr7dls9W2vh4ESpWsHfN`",
				"var squareToken = \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"$squareToken .= \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"{\n    \"square_token\": \"EAAAb0fr7dls9W2vh4ESpWsHfN\"\n}",
				"<squareToken>\n    EAAAb0fr7dls9W2vh4ESpWsHfN\n</squareToken>",
				"squareToken := \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"squareToken = 'EAAAb0fr7dls9W2vh4ESpWsHfN'",
				"square_TOKEN = \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"square_TOKEN := \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"square_TOKEN ?= \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"squareToken = EAAAb0fr7dls9W2vh4ESpWsHfN",
				"string squareToken = \"EAAAb0fr7dls9W2vh4ESpWsHfN\";",
				"var squareToken string = \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"String squareToken = \"EAAAb0fr7dls9W2vh4ESpWsHfN\";",
				"System.setProperty(\"SQUARE_TOKEN\", \"EAAAb0fr7dls9W2vh4ESpWsHfN\")",
				"  \"squareToken\" => \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"square_TOKEN ::= \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"square_TOKEN :::= \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"squareToken=\"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"squareToken = \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"square_token: EAAAb0fr7dls9W2vh4ESpWsHfN",
				"square_token: \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"squareToken = \"EAAAb0fr7dls9W2vh4ESpWsHfN\"",
				"ARG token=sq0atp-812erere3wewew45678901",
				"ARG token=EAAAlsBxkkVgvmr7FasTFbM6VUGZ31EJ4jZKTJZySgElBDJ_wyafHuBFquFexY7E",
			},
			falsePositives: []string{
				`aws-cli@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(SquareAccessToken())
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
