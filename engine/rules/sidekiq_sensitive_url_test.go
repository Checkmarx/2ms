package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSidekiqSensitiveUrl(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SidekiqSensitiveUrl validation",
			truePositives: []string{
				"https://cafebabe:deadbeef@gems.contribsys.com/",
				"https://cafebabe:deadbeef@gems.contribsys.com",
				"https://cafeb4b3:d3adb33f@enterprise.contribsys.com/",
				"https://cafeb4b3:d3adb33f@enterprise.contribsys.com",
				"http://cafebabe:deadbeef@gems.contribsys.com/",
				"http://cafebabe:deadbeef@gems.contribsys.com",
				"http://cafeb4b3:d3adb33f@enterprise.contribsys.com/",
				"http://cafeb4b3:d3adb33f@enterprise.contribsys.com",
				"http://cafeb4b3:d3adb33f@enterprise.contribsys.com#heading1",
				"http://cafeb4b3:d3adb33f@enterprise.contribsys.com?param1=true&param2=false",
				"http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80",
				"http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(SidekiqSensitiveUrl())
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
