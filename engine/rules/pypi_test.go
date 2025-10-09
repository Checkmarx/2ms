package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPyPiUploadToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "PyPiUploadToken validation",
			truePositives: []string{
				"string pypiToken = \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\";",
				"var pypiToken string = \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"String pypiToken = \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\";",
				"var pypiToken = \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"System.setProperty(\"PYPI_TOKEN\", \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\")",
				"  \"pypiToken\" => \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypi_TOKEN := \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypiToken = \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"{\n    \"pypi_token\": \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"\n}",
				"{\"config.ini\": \"PYPI_TOKEN=pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\\nBACKUP_ENABLED=true\"}",
				"pypi_token: pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077",
				"pypiToken := \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypiToken = \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypi_TOKEN = \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypi_TOKEN :::= \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypiToken = pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077",
				"<pypiToken>\n    pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\n</pypiToken>",
				"pypi_token: 'pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077'",
				"pypi_token: \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypiToken := `pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077`",
				"pypi_TOKEN ::= \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypi_TOKEN ?= \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypiToken=\"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypiToken=pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077",
				"$pypiToken .= \"pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077\"",
				"pypiToken = 'pypi-AgEIcHlwaS5vcmc8ddbe16566126f42aef044df732220778ddbe16566126f42aef044df73222077'",
			},
			falsePositives: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(PyPiUploadToken())
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
