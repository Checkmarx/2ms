package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCoinbaseAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "CoinbaseAccessToken validation",
			truePositives: []string{
				"coinbaseToken = '_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m'",
				"System.setProperty(\"COINBASE_TOKEN\", \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\")",
				"coinbase_TOKEN = \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbase_TOKEN :::= \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbaseToken = _lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m",
				"{\n    \"coinbase_token\": \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"\n}",
				"string coinbaseToken = \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\";",
				"String coinbaseToken = \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\";",
				"coinbaseToken = \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbase_TOKEN ::= \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbase_TOKEN ?= \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"{\"config.ini\": \"COINBASE_TOKEN=_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\\nBACKUP_ENABLED=true\"}",
				"coinbase_token: '_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m'",
				"var coinbaseToken = \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbase_TOKEN := \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbaseToken=\"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbaseToken = \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbaseToken=_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m",
				"<coinbaseToken>\n    _lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\n</coinbaseToken>",
				"coinbase_token: _lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m",
				"var coinbaseToken string = \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbaseToken := `_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m`",
				"  \"coinbaseToken\" => \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbase_token: \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"coinbaseToken := \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
				"$coinbaseToken .= \"_lobtsmct2rizqh04jb8772k2md13gyeyrgahfsc9brmo_b-0zhe0v-mo-olf30m\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(CoinbaseAccessToken())
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
