package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArtifactoryApiKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ArtifactoryApiKey validation",
			truePositives: []string{
				"artifactoryApiKey := \"AKCpun7ticu8kdaj84nu7yi4jonxfl4010lixh16xcgm4x1t528hqupjk1p8mk8jiag7zu7vb\"",
			},
			falsePositives: []string{
				`lowEntropy := AKCpXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
				"wrongStart := \"AkCpun7ticu8kdaj84nu7yi4jonxfl4010lixh16xcgm4x1t528hqupjk1p8mk8jiag7zu7vb\"",
				"wrongLength := \"AkCpun7ticu8kdaj84nu7yi4jonxfl4010lixh16xcgm4x1t528hqupjk1p8mk8\"",
				"partOfAlongUnrelatedBlob gYnkgAkCpfoty5jzxcfnsrmz4lya4lcqjuss1sk7bnj0ufk07cmq46opngxv2oacso8hc5z104liy0VyZSB2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("truePositives := []string{")
			for _, s := range tt.truePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			fmt.Println("falsePositives := []string{")
			for _, s := range tt.falsePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(ArtifactoryApiKey())
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
