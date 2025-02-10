package cmd

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateFormat(t *testing.T) {
	tests := []struct {
		name            string
		stdoutFormatVar string
		reportPath      []string
		expectedErr     error
	}{
		{
			name:            "valid output format and report extension json",
			stdoutFormatVar: "json",
			reportPath:      []string{"report.json"},
			expectedErr:     nil,
		},
		{
			name:            "valid output format and report extension yaml",
			stdoutFormatVar: "yaml",
			reportPath:      []string{"report.yaml"},
			expectedErr:     nil,
		},
		{
			name:            "valid output format and report extension sarif",
			stdoutFormatVar: "sarif",
			reportPath:      []string{"report.sarif"},
			expectedErr:     nil,
		},
		{
			name:            "invalid output format",
			stdoutFormatVar: "invalid",
			reportPath:      []string{"report.json"},
			expectedErr:     fmt.Errorf("invalid output format: invalid, available formats are: json, yaml and sarif"),
		},
		{
			name:            "invalid report extension",
			stdoutFormatVar: "json",
			reportPath:      []string{"report.invalid"},
			expectedErr:     fmt.Errorf("invalid report extension: invalid, available extensions are: json, yaml and sarif"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFormat(tt.stdoutFormatVar, tt.reportPath)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}
