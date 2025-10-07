package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodecovAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "CodecovAccessToken validation",
			truePositives: []string{
				"codecovToken = \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecovToken=sk426s9rtd2dyxmchsd0g5dx20zqqdio",
				"<codecovToken>\n    sk426s9rtd2dyxmchsd0g5dx20zqqdio\n</codecovToken>",
				"var codecovToken string = \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecovToken := \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecovToken = 'sk426s9rtd2dyxmchsd0g5dx20zqqdio'",
				"codecovToken = \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"System.setProperty(\"CODECOV_TOKEN\", \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\")",
				"codecovToken=\"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecov_token: sk426s9rtd2dyxmchsd0g5dx20zqqdio",
				"codecov_token: 'sk426s9rtd2dyxmchsd0g5dx20zqqdio'",
				"String codecovToken = \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\";",
				"$codecovToken .= \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"  \"codecovToken\" => \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecov_TOKEN := \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecov_TOKEN ::= \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecovToken = sk426s9rtd2dyxmchsd0g5dx20zqqdio",
				"{\n    \"codecov_token\": \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"\n}",
				"{\"config.ini\": \"CODECOV_TOKEN=sk426s9rtd2dyxmchsd0g5dx20zqqdio\\nBACKUP_ENABLED=true\"}",
				"codecovToken := `sk426s9rtd2dyxmchsd0g5dx20zqqdio`",
				"codecov_TOKEN = \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecov_token: \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"string codecovToken = \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\";",
				"var codecovToken = \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecov_TOKEN :::= \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
				"codecov_TOKEN ?= \"sk426s9rtd2dyxmchsd0g5dx20zqqdio\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(CodecovAccessToken())
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
