package linecontent

import (
	"fmt"
	"strings"
)

const (
	lineMaxParseSize      = 10000
	contextLeftSizeLimit  = 250
	contextRightSizeLimit = 250
)

func GetLineContent(line, secret string) (string, error) {
	lineSize := len(line)
	if lineSize == 0 {
		return "", fmt.Errorf("failed to get line content: line empty")
	}

	if len(secret) == 0 {
		return "", fmt.Errorf("failed to get line content: secret empty")
	}

	// Truncate lineContent to max size
	if lineSize > lineMaxParseSize {
		line = line[:lineMaxParseSize]
		lineSize = lineMaxParseSize
	}

	// Find the secret's position in the line
	secretStartIndex := strings.Index(line, secret)
	if secretStartIndex == -1 {
		// Secret not found, return truncated content based on context limits
		maxSize := contextLeftSizeLimit + contextRightSizeLimit
		if lineSize < maxSize {
			return line, nil
		}
		return line[:maxSize], nil
	}

	// Calculate bounds for the result
	secretEndIndex := secretStartIndex + len(secret)
	start := max(secretStartIndex-contextLeftSizeLimit, 0)
	end := min(secretEndIndex+contextRightSizeLimit, lineSize)

	return line[start:end], nil
}
