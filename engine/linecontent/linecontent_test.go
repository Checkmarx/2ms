package linecontent

import (
	"strings"
	"testing"
)

const (
	dummySecret = "DummySecret"
)

func TestGetLineContent(t *testing.T) {
	tests := []struct {
		name         string
		line         string
		secret       string
		expected     string
		error        bool
		errorMessage string
	}{
		{
			name:         "Empty line",
			line:         "",
			secret:       dummySecret,
			expected:     "",
			error:        true,
			errorMessage: "line empty",
		},
		{
			name:         "Empty secret",
			line:         "line",
			secret:       "",
			expected:     "",
			error:        true,
			errorMessage: "secret empty",
		},
		{
			name:     "Secret not found with line size smaller than the parse limit",
			line:     "Dummy content line",
			secret:   dummySecret,
			expected: "Dummy content line",
			error:    false,
		},
		{
			name:   "Secret not found with secret present and line size larger than the parse limit",
			line:   "This is the start of a big line content" + strings.Repeat("A", lineMaxParseSize) + dummySecret,
			secret: dummySecret,
			expected: "This is the start of a big line content" + strings.Repeat(
				"A",
				contextLeftSizeLimit+contextRightSizeLimit-len("This is the start of a big line content"),
			),
			error: false,
		},
		{
			name:     "Secret larger than the line",
			line:     strings.Repeat("B", contextLeftSizeLimit) + strings.Repeat("A", contextRightSizeLimit),
			secret:   "large secret" + strings.Repeat("B", contextRightSizeLimit+contextLeftSizeLimit+100),
			expected: strings.Repeat("B", contextLeftSizeLimit) + strings.Repeat("A", contextRightSizeLimit),
			error:    false,
		},
		{
			name:     "Secret at the beginning with line size smaller than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("A", lineMaxParseSize/2),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("A", contextRightSizeLimit),
			error:    false,
		},
		{
			name: "Secret found in middle with line size smaller than the parse limit",
			line: "start" + strings.Repeat(
				"A",
				contextLeftSizeLimit,
			) + dummySecret + strings.Repeat(
				"A",
				contextRightSizeLimit,
			) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("A", contextLeftSizeLimit) + dummySecret + strings.Repeat("A", contextRightSizeLimit),
			error:    false,
		},
		{
			name:     "Secret at the end with line size smaller than the parse limit",
			line:     strings.Repeat("A", lineMaxParseSize/2) + dummySecret + ":end",
			secret:   dummySecret,
			expected: strings.Repeat("A", contextLeftSizeLimit) + dummySecret + ":end",
			error:    false,
		},
		{
			name:     "Secret at the beginning with line size larger than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("A", lineMaxParseSize),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("A", contextRightSizeLimit),
			error:    false,
		},
		{
			name:     "Secret found in middle with line size larger than the parse limit",
			line:     "start" + strings.Repeat("A", contextLeftSizeLimit) + dummySecret + strings.Repeat("A", lineMaxParseSize) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("A", contextLeftSizeLimit) + dummySecret + strings.Repeat("A", contextRightSizeLimit),
			error:    false,
		},
		{
			name:     "Secret at the end with line size larger than the parse limit",
			line:     strings.Repeat("A", lineMaxParseSize-100) + dummySecret + strings.Repeat("A", lineMaxParseSize),
			secret:   dummySecret,
			expected: strings.Repeat("A", contextLeftSizeLimit) + dummySecret + strings.Repeat("A", 100-len(dummySecret)),
			error:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetLineContent(tt.line, tt.secret)
			if (err != nil) != tt.error {
				t.Fatalf("GetLineContent() error = %v, wantErr %v", err, tt.error)
			}
			if err != nil && err.Error() != tt.errorMessage {
				t.Errorf("GetLineContent() error message = %v, want %v", err.Error(), tt.errorMessage)
			}
			if got != tt.expected {
				t.Errorf("GetLineContent() = %v, want %v", got, tt.expected)
			}
		})
	}
}
