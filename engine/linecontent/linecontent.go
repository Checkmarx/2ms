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

func GetLineContent(line, secret string, startColumn int) (string, error) {
	lineSize := len(line)
	if lineSize == 0 {
		return "", fmt.Errorf("line empty")
	}

	if secret == "" {
		return "", fmt.Errorf("secret empty")
	}

	// Truncate lineContent to max size, centering the window on startColumn so a secret
	// far into a very long line isn't truncated away before it can be found.
	if lineSize > lineMaxParseSize {
		windowStart := 0
		if hint := startColumn - 1; hint >= 0 && hint < lineSize {
			windowStart = max(hint-lineMaxParseSize/2, 0)
			windowStart = min(windowStart, lineSize-lineMaxParseSize)
		}
		line = line[windowStart : windowStart+lineMaxParseSize]
		lineSize = lineMaxParseSize
		startColumn -= windowStart
	}

	// Find the secret's position in the line, searching from the match's start column
	// onwards first so that repeated occurrences of secret in the line are disambiguated.
	secretStartIndex := -1
	hint := startColumn - 1
	if hint >= 0 && hint < lineSize {
		if idx := strings.Index(line[hint:], secret); idx != -1 {
			secretStartIndex = hint + idx
		}
	}
	if secretStartIndex == -1 {
		secretStartIndex = strings.Index(line, secret)
	}
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
