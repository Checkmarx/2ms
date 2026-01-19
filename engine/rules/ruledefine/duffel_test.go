package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDuffelAPIToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Duffel validation",
			truePositives: []string{
				"duffel_TOKEN ::= \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"duffel_TOKEN ?= \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"<duffelToken>\n    duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\n</duffelToken>",
				"duffel_token: 'duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12'",
				"string duffelToken = \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\";",
				"duffelToken := `duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12`",
				"System.setProperty(\"DUFFEL_TOKEN\", \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\")",
				"duffelToken=\"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"duffelToken=duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12",
				"{\"config.ini\": \"DUFFEL_TOKEN=duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\\nBACKUP_ENABLED=true\"}",
				"$duffelToken .= \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"duffelToken = 'duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12'",
				"  \"duffelToken\" => \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"duffel_TOKEN := \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"duffelToken = \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"duffelToken = duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12",
				"{\n    \"duffel_token\": \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"\n}",
				"duffelToken := \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"String duffelToken = \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\";",
				"duffelToken = \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"duffel_TOKEN = \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"duffel_TOKEN :::= \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"duffel_token: duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12",
				"duffel_token: \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"var duffelToken string = \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
				"var duffelToken = \"duffel_test_=3hohxcvsikfv-ja4nbtsihjmq0vqr81cvkfgbrsn12\"",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(Duffel())
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
