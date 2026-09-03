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

	// For lines > lineMaxParseSize, get just the necessary context around the secret
	if lineSize > lineMaxParseSize {
		matchStartIndex := startColumn - 1
		windowStart := 0
		if matchStartIndex >= 0 && matchStartIndex < lineSize {
			windowStart = max(matchStartIndex-lineMaxParseSize/2, 0)
			// adjust line context window if windowStart+lineMaxParseSize would be higher than lineSize
			windowStart = min(windowStart, lineSize-lineMaxParseSize)
		}
		line = line[windowStart : windowStart+lineMaxParseSize]
		lineSize = lineMaxParseSize
		startColumn -= windowStart
	}

	// The same secret value can appear more than once on a line. Search for it at the relevant index for this secret instance
	secretStartIndex := -1
	matchStartIndex := startColumn - 1
	if matchStartIndex >= 0 && matchStartIndex < lineSize {
		if idx := strings.Index(line[matchStartIndex:], secret); idx != -1 {
			secretStartIndex = matchStartIndex + idx
		}
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
