package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func TestNugetConfigPassword(t *testing.T) {
	tests := []struct {
		name                 string
		truePositivesWPaths  map[string]string
		falsePositivesWPaths map[string]string
	}{
		{
			name: "NugetConfigPassword validation",
			truePositivesWPaths: map[string]string{
				"nuget.config": `<add key="Password" value="CleartextPassword1" />`,
				"Nuget.config": `<add key="ClearTextPassword" value="CleartextPassword1" />`,
				"Nuget.Config": `<add key="ClearTextPassword" value="TestSourcePassword" />`,
				"Nuget.COnfig": `<add key="ClearTextPassword" value="TestSource-Password" />`,
				"Nuget.CONfig": `<add key="ClearTextPassword" value="TestSource%Password" />`,
				"Nuget.CONFig": `<add key="ClearTextPassword" value="TestSource%Password%" />`,
			},
			falsePositivesWPaths: map[string]string{
				"some.xml":     `<add key="Password" value="CleartextPassword1" />`,            // wrong filename
				"nuget.config": `<add key="ClearTextPassword" value="XXXXXXXXXXX" />`,          // low entropy
				"Nuget.config": `<add key="ClearTextPassword" value="abc" />`,                  // too short
				"Nuget.Config": `<add key="ClearTextPassword" value="%TestSourcePassword%" />`, // environment variable
				"NUget.Config": `<add key="ClearTextPassword" value="33f!!lloppa" />`,          // known sample
				"NUGet.Config": `<add key="ClearTextPassword" value="hal+9ooo_da!sY" />`,       // known sample
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(NugetConfigPassword())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for path, truePositive := range tt.truePositivesWPaths {
				fragment := detect.Fragment{Raw: truePositive, FilePath: path}
				findings := d.Detect(fragment)
				assert.Equal(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			// validate false positives if any specified
			for path, falsePositive := range tt.falsePositivesWPaths {
				fragment := detect.Fragment{Raw: falsePositive, FilePath: path}
				findings := d.Detect(fragment)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
