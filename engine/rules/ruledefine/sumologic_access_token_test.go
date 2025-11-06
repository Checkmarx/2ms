package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSumoLogicAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name:          "SumoLogicAccessToken validation",
			truePositives: []string{},
			falsePositives: []string{
				`#   SUMO_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // gitleaks:allow
				"-e SUMO_ACCESS_KEY=`etcdctl get /sumologic_secret`",
				`SUMO_ACCESS_KEY={SumoAccessKey}`,
				`SUMO_ACCESS_KEY=${SUMO_ACCESS_KEY:=$2}`,
				`sumo_access_key   = "<SUMOLOGIC ACCESS KEY>"`,
				`SUMO_ACCESS_KEY: AbCeFG123`,
				`sumOfExposures = 3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5;`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(SumoLogicAccessToken())
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
