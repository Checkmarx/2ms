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
		name     string
		line     string
		secret   string
		expected string
	}{
		{
			name:     "Empty line",
			line:     "",
			secret:   dummySecret,
			expected: "",
		},
		{
			name:     "Empty secret",
			line:     "line",
			secret:   "",
			expected: "",
		},
		{
			name:     "Secret not found with line size smaller than the parse limit",
			line:     "Dummy content line",
			secret:   dummySecret,
			expected: "Dummy content line",
		},
		{
			name:     "Secret not found with secret present and line size larger than the parse limit",
			line:     "This is the start of a big line content" + strings.Repeat("A", lineContentMaxParseSize) + dummySecret,
			secret:   dummySecret,
			expected: "This is the start of a big line content" + strings.Repeat("A", contextLeftSizeLimit+contextRightSizeLimit-len("This is the start of a big line content")),
		},
		{
			name:     "Secret larger than the line",
			line:     strings.Repeat("B", contextLeftSizeLimit) + strings.Repeat("A", contextRightSizeLimit),
			secret:   "large secret" + strings.Repeat("B", contextRightSizeLimit+contextLeftSizeLimit+100),
			expected: strings.Repeat("B", contextLeftSizeLimit) + strings.Repeat("A", contextRightSizeLimit),
		},
		{
			name:     "Secret at the beginning with line size smaller than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("A", lineContentMaxParseSize/2),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("A", contextRightSizeLimit),
		},
		{
			name:     "Secret found in middle with line size smaller than the parse limit",
			line:     "start" + strings.Repeat("A", contextLeftSizeLimit) + dummySecret + strings.Repeat("A", contextRightSizeLimit) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("A", contextLeftSizeLimit) + dummySecret + strings.Repeat("A", contextRightSizeLimit),
		},
		{
			name:     "Secret at the end with line size smaller than the parse limit",
			line:     strings.Repeat("A", lineContentMaxParseSize/2) + dummySecret + ":end",
			secret:   dummySecret,
			expected: strings.Repeat("A", contextLeftSizeLimit) + dummySecret + ":end",
		},
		{
			name:     "Secret at the beginning with line size larger than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("A", lineContentMaxParseSize),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("A", contextRightSizeLimit),
		},
		{
			name:     "Secret found in middle with line size larger than the parse limit",
			line:     "start" + strings.Repeat("A", contextLeftSizeLimit) + dummySecret + strings.Repeat("A", lineContentMaxParseSize) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("A", contextLeftSizeLimit) + dummySecret + strings.Repeat("A", contextRightSizeLimit),
		},
		{
			name:     "Secret at the end with line size larger than the parse limit",
			line:     strings.Repeat("A", lineContentMaxParseSize-100) + dummySecret + strings.Repeat("A", lineContentMaxParseSize),
			secret:   dummySecret,
			expected: strings.Repeat("A", contextLeftSizeLimit) + dummySecret + strings.Repeat("A", calculateRepeatForSecretAtTheEndWithLargerThanParseLimit(100, 1, len(dummySecret))),
		},
		{
			name:     "Secret at the beginning with line containing 2 byte chars and size smaller than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("é", lineContentMaxParseSize/4),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("é", contextRightSizeLimit),
		},
		{
			name:     "Secret found in middle with line containing 2 byte chars and size smaller than the parse limit",
			line:     "start" + strings.Repeat("é", contextLeftSizeLimit) + dummySecret + strings.Repeat("é", contextRightSizeLimit) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("é", contextLeftSizeLimit) + dummySecret + strings.Repeat("é", contextRightSizeLimit),
		},
		{
			name:     "Secret at the end with line containing 2 byte chars and size smaller than the parse limit",
			line:     strings.Repeat("é", lineContentMaxParseSize/4) + dummySecret + ":end",
			secret:   dummySecret,
			expected: strings.Repeat("é", contextLeftSizeLimit) + dummySecret + ":end",
		},
		{
			name:     "Secret at the beginning with line containing 2 byte chars and size larger than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("é", lineContentMaxParseSize/2),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("é", contextRightSizeLimit),
		},
		{
			name:     "Secret found in middle with line containing 2 byte chars and size larger than the parse limit",
			line:     "start" + strings.Repeat("é", contextLeftSizeLimit) + dummySecret + strings.Repeat("é", lineContentMaxParseSize/2) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("é", contextLeftSizeLimit) + dummySecret + strings.Repeat("é", contextRightSizeLimit),
		},
		{
			name:     "Secret at the end with line containing 2 byte chars and size larger than the parse limit",
			line:     strings.Repeat("é", lineContentMaxParseSize/2-100) + dummySecret + strings.Repeat("é", lineContentMaxParseSize/2),
			secret:   dummySecret,
			expected: strings.Repeat("é", contextLeftSizeLimit) + dummySecret + strings.Repeat("é", calculateRepeatForSecretAtTheEndWithLargerThanParseLimit(100, 2, len(dummySecret))),
		},
		{
			name:     "Secret at the beginning with line containing 3 byte chars and size smaller than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("ࠚ", lineContentMaxParseSize/6),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("ࠚ", contextRightSizeLimit),
		},
		{
			name:     "Secret found in middle with line containing 3 byte chars and size smaller than the parse limit",
			line:     "start" + strings.Repeat("ࠚ", contextLeftSizeLimit) + dummySecret + strings.Repeat("ࠚ", contextRightSizeLimit) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("ࠚ", contextLeftSizeLimit) + dummySecret + strings.Repeat("ࠚ", contextRightSizeLimit),
		},
		{
			name:     "Secret at the end with line containing 3 byte chars and size smaller than the parse limit",
			line:     strings.Repeat("ࠚ", lineContentMaxParseSize/6) + dummySecret + ":end",
			secret:   dummySecret,
			expected: strings.Repeat("ࠚ", contextLeftSizeLimit) + dummySecret + ":end",
		},
		{
			name:     "Secret at the beginning with line containing 3 byte chars and size larger than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("ࠚ", lineContentMaxParseSize/3),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("ࠚ", contextRightSizeLimit),
		},
		{
			name:     "Secret found in middle with line containing 3 byte chars and size larger than the parse limit",
			line:     "start" + strings.Repeat("ࠚ", contextLeftSizeLimit) + dummySecret + strings.Repeat("ࠚ", lineContentMaxParseSize/3) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("ࠚ", contextLeftSizeLimit) + dummySecret + strings.Repeat("ࠚ", contextRightSizeLimit),
		},
		{
			name:     "Secret at the end with line containing 3 byte chars and size larger than the parse limit",
			line:     strings.Repeat("ࠚ", lineContentMaxParseSize/3-100) + dummySecret + strings.Repeat("ࠚ", lineContentMaxParseSize/3),
			secret:   dummySecret,
			expected: strings.Repeat("ࠚ", contextLeftSizeLimit) + dummySecret + strings.Repeat("ࠚ", calculateRepeatForSecretAtTheEndWithLargerThanParseLimit(100, 3, len(dummySecret))),
		},
		{
			name:     "Secret at the beginning with line containing 4 byte chars and size smaller than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("𝄞", lineContentMaxParseSize/8),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("𝄞", contextRightSizeLimit),
		},
		{
			name:     "Secret found in middle with line containing 4 byte chars and size smaller than the parse limit",
			line:     "start" + strings.Repeat("𝄞", contextLeftSizeLimit) + dummySecret + strings.Repeat("𝄞", contextRightSizeLimit) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("𝄞", contextLeftSizeLimit) + dummySecret + strings.Repeat("𝄞", contextRightSizeLimit),
		},
		{
			name:     "Secret at the end with line containing 4 byte chars and size smaller than the parse limit",
			line:     strings.Repeat("𝄞", lineContentMaxParseSize/8) + dummySecret + ":end",
			secret:   dummySecret,
			expected: strings.Repeat("𝄞", contextLeftSizeLimit) + dummySecret + ":end",
		},
		{
			name:     "Secret at the beginning with line containing 4 byte chars and size larger than the parse limit",
			line:     "start:" + dummySecret + strings.Repeat("𝄞", lineContentMaxParseSize/4),
			secret:   dummySecret,
			expected: "start:" + dummySecret + strings.Repeat("𝄞", contextRightSizeLimit),
		},
		{
			name:     "Secret found in middle with line containing 4 byte chars and size larger than the parse limit",
			line:     "start" + strings.Repeat("𝄞", contextLeftSizeLimit) + dummySecret + strings.Repeat("𝄞", lineContentMaxParseSize/4) + "end",
			secret:   dummySecret,
			expected: strings.Repeat("𝄞", contextLeftSizeLimit) + dummySecret + strings.Repeat("𝄞", contextRightSizeLimit),
		},
		{
			name:     "Secret at the end with line containing 4 byte chars and size larger than the parse limit",
			line:     strings.Repeat("𝄞", lineContentMaxParseSize/4-100) + dummySecret + strings.Repeat("𝄞", lineContentMaxParseSize/4),
			secret:   dummySecret,
			expected: strings.Repeat("𝄞", contextLeftSizeLimit) + dummySecret + strings.Repeat("𝄞", calculateRepeatForSecretAtTheEndWithLargerThanParseLimit(100, 4, len(dummySecret))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetLineContent(tt.line, tt.secret)
			if got != tt.expected {
				t.Errorf("GetLineContent() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func calculateRepeatForSecretAtTheEndWithLargerThanParseLimit(offset, bytes, secretLength int) int {
	remainingSize := lineContentMaxParseSize - ((lineContentMaxParseSize/bytes - offset) * bytes) - secretLength
	return (remainingSize - ((3 - ((remainingSize) % bytes)) * bytes)) / bytes
}
