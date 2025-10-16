package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func TestFreemiusSecretKey(t *testing.T) {
	tests := []struct {
		name                 string
		truePositivesWPaths  map[string]string
		falsePositivesWPaths map[string]string
	}{
		{
			name: "FreemiusSecretKey validation",
			truePositivesWPaths: map[string]string{
				"file.php": `$config = array(
			"secret_key" => "sk_ubb4yN3mzqGR2x8#P7r5&@*xC$utE",
		);`,
			},
			falsePositivesWPaths: map[string]string{
				// Invalid format: missing quotes around `secret_key`.
				"foo.php": `$config = array(
			secret_key => "sk_abcdefghijklmnopqrstuvwxyz123",
		);`,
				// Invalid format: missing quotes around the key value.
				"bar.php": `$config = array(
			"secret_key" => sk_abcdefghijklmnopqrstuvwxyz123,
		);`,
				// Invalid: different key name.
				"baz.php": `$config = array(
			"other_key" => "sk_abcdefghijklmnopqrstuvwxyz123",
		);`,
				// Invalid: file extension, should validate only .php files.
				"foo.html": `$config = array(
					"secret_key" => "sk_ubb4yN3mzqGR2x8#P7r5&@*xC$utE",
				);`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(Freemius())
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
