package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestFilter(t *testing.T) {
	tests := []struct {
		name           string
		findings       []report.Finding
		redact         uint
		expectedCount  int
		expectedSecret string // for single finding tests
	}{
		{
			name: "valid finding passes through",
			findings: []report.Finding{
				{Secret: "my-secret", Line: "password=my-secret", RuleID: "test-rule"},
			},
			redact:         0,
			expectedCount:  1,
			expectedSecret: "my-secret",
		},
		{
			name: "empty secret is filtered out",
			findings: []report.Finding{
				{Secret: "", Line: "some line content", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "empty line is filtered out",
			findings: []report.Finding{
				{Secret: "my-secret", Line: "", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "whitespace-only secret is filtered out",
			findings: []report.Finding{
				{Secret: "   ", Line: "some line content", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "whitespace-only line is filtered out",
			findings: []report.Finding{
				{Secret: "my-secret", Line: "   ", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "newline-only line is filtered out",
			findings: []report.Finding{
				{Secret: "my-secret", Line: "\n", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "carriage-return-only line is filtered out",
			findings: []report.Finding{
				{Secret: "my-secret", Line: "\r", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "newline and carriage return line is filtered out",
			findings: []report.Finding{
				{Secret: "my-secret", Line: "\r\n", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "tab-only line is filtered out",
			findings: []report.Finding{
				{Secret: "my-secret", Line: "\t", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "mixed whitespace line is filtered out",
			findings: []report.Finding{
				{Secret: "my-secret", Line: " \t\n\r ", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "newline-only secret is filtered out",
			findings: []report.Finding{
				{Secret: "\n", Line: "some line content", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 0,
		},
		{
			name: "mixed valid and invalid findings",
			findings: []report.Finding{
				{Secret: "valid-secret", Line: "password=valid-secret", RuleID: "test-rule"},
				{Secret: "", Line: "some line", RuleID: "test-rule"},
				{Secret: "another-secret", Line: "", RuleID: "test-rule"},
				{Secret: "   ", Line: "line", RuleID: "test-rule"},
				{Secret: "good-secret", Line: "api_key=good-secret", RuleID: "test-rule"},
			},
			redact:        0,
			expectedCount: 2,
		},
		{
			name:          "empty findings list",
			findings:      []report.Finding{},
			redact:        0,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter(tt.findings, tt.redact)
			assert.Equal(t, tt.expectedCount, len(result), "unexpected number of findings")

			if tt.expectedCount == 1 && tt.expectedSecret != "" {
				assert.Equal(t, tt.expectedSecret, result[0].Secret, "unexpected secret value")
			}
		})
	}
}

