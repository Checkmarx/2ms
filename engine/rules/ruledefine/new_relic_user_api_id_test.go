package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRelicUserAPIID(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "NewRelicUserKey validation",
			truePositives: []string{
				"var new-relicToken = \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relicToken=\"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relicToken=xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw",
				"new-relicToken = xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw",
				"new-relic_TOKEN = \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relic_TOKEN := \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relic_TOKEN ::= \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relic_TOKEN :::= \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"<new-relicToken>\n    xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\n</new-relicToken>",
				"new-relic_token: 'xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw'",
				"var new-relicToken string = \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relicToken = \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"System.setProperty(\"NEW-RELIC_TOKEN\", \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\")",
				"  \"new-relicToken\" => \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relic_TOKEN ?= \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relicToken = \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"{\n    \"new-relic_token\": \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"\n}",
				"{\"config.ini\": \"NEW-RELIC_TOKEN=xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\\nBACKUP_ENABLED=true\"}",
				"new-relic_token: xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw",
				"string new-relicToken = \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\";",
				"$new-relicToken .= \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relicToken = 'xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw'",
				"new-relic_token: \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relicToken := \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\"",
				"new-relicToken := `xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw`",
				"String new-relicToken = \"xzx6bzhs42mhrodqbvl7941mim7nzgel0kvddv1jzihkixipi00ebd8mjsocygaw\";",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(NewRelicUserKey())
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
