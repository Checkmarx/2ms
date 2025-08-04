package detect

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zricethezav/gitleaks/v8/report"
)

func TestIsNew(t *testing.T) {
	tests := []struct {
		findings report.Finding
		baseline []report.Finding
		expect   bool
	}{
		{
			findings: report.Finding{
				Author: "a",
				Commit: "0000",
			},
			baseline: []report.Finding{
				{
					Author: "a",
					Commit: "0000",
				},
			},
			expect: false,
		},
		{
			findings: report.Finding{
				Author: "a",
				Commit: "0000",
			},
			baseline: []report.Finding{
				{
					Author: "a",
					Commit: "0002",
				},
			},
			expect: true,
		},
		{
			findings: report.Finding{
				Author: "a",
				Commit: "0000",
				Tags:   []string{"a", "b"},
			},
			baseline: []report.Finding{
				{
					Author: "a",
					Commit: "0000",
					Tags:   []string{"a", "c"},
				},
			},
			expect: false, // Updated tags doesn't make it a new finding
		},
	}
	for _, test := range tests {
		assert.Equal(t, test.expect, IsNew(&test.findings, test.baseline))
	}
}

func TestFileLoadBaseline(t *testing.T) {
	tests := []struct {
		Filename      string
		ExpectedError error
	}{
		{
			Filename:      "../../tests/testData/baseline/baseline.csv",
			ExpectedError: errors.New("the format of the file ../../tests/testData/baseline/baseline.csv is not supported"),
		},
		{
			Filename:      "../../tests/testData/baseline/baseline.sarif",
			ExpectedError: errors.New("the format of the file ../../tests/testData/baseline/baseline.sarif is not supported"),
		},
		{
			Filename:      "../../tests/testData/baseline/notfound.json",
			ExpectedError: errors.New("could not open ../../tests/testData/baseline/notfound.json"),
		},
	}

	for _, test := range tests {
		_, err := LoadBaseline(test.Filename)
		assert.Equal(t, test.ExpectedError, err)
	}
}
