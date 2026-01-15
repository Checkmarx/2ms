package ruledefine

import (
	"fmt"
	"testing"

	"github.com/checkmarx/2ms/v4/engine/detect"
	"github.com/stretchr/testify/assert"
)

func TestHashicorpField(t *testing.T) {
	tests := []struct {
		name                 string
		truePositivesWPaths  map[string]string
		falsePositivesWPaths map[string]string
	}{
		{
			name: "HashicorpField validation",
			truePositivesWPaths: map[string]string{
				// Example from: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server.html
				"file.tf": "administrator_login_password = " + `"thisIsDog11"`,
				// https://registry.terraform.io/providers/petoju/mysql/latest/docs
				"file.hcl": "password       = " + `"rootpasswd"`,
			},
			falsePositivesWPaths: map[string]string{
				"file.tf":      "administrator_login_password = var.db_password",
				"file.hcl":     `password = "${aws_db_instance.default.password}"`,
				"unrelated.js": "password       = " + `"rootpasswd"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(HashicorpField())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for path, truePositive := range tt.truePositivesWPaths {
				fragment := detect.Fragment{Raw: truePositive, FilePath: path}
				findings := d.Detect(&fragment)
				assert.Equal(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			// validate false positives if any specified
			for path, falsePositive := range tt.falsePositivesWPaths {
				fragment := detect.Fragment{Raw: falsePositive, FilePath: path}
				findings := d.Detect(&fragment)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
