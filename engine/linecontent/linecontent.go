package linecontent

const (
	lineContentMaxParseSize = 10000
	contextLeftSizeLimit    = 250
	contextRightSizeLimit   = 250
)

func GetLineContent(line, secret string) string {
	lineSize := len(line)
	if lineSize == 0 || len(secret) == 0 {
		return ""
	}

	// Truncate line to max parse size before converting to runes
	shouldRemoveLastChars := false
	if lineSize > lineContentMaxParseSize {
		line = line[:lineContentMaxParseSize]
		shouldRemoveLastChars = true // to prevent issues when truncating a multibyte character in the middle
	}

	// Convert line and secret to runes
	lineRunes, lineRunesSize := getLineRunes(line, shouldRemoveLastChars)
	secretRunes := []rune(secret)
	secretRunesSize := len(secretRunes)

	// Find the secret's position in the line (working with runes)
	secretStartIndex := indexOf(lineRunes, secretRunes, lineRunesSize, secretRunesSize)
	if secretStartIndex == -1 {
		// Secret not found, return truncated content based on context limits
		maxSize := contextLeftSizeLimit + contextRightSizeLimit
		if lineRunesSize < maxSize {
			return string(lineRunes)
		}
		return string(lineRunes[:maxSize])
	}

	// Calculate bounds for the result
	secretEndIndex := secretStartIndex + secretRunesSize
	start := max(secretStartIndex-contextLeftSizeLimit, 0)
	end := min(secretEndIndex+contextRightSizeLimit, lineRunesSize)

	return string(lineRunes[start:end])
}

func getLineRunes(line string, shouldRemoveLastChars bool) ([]rune, int) {
	lineRunes := []rune(line)
	lineRunesSize := len(lineRunes)
	if shouldRemoveLastChars {
		// A single rune can be up to 4 bytes in UTF-8 encoding.
		// If truncation occurs in the middle of a multibyte character,
		// it will leave a partial byte sequence, potentially consisting of
		// up to 3 bytes. Each of these remaining bytes will be treated
		// as an invalid character, displayed as a replacement character (�).
		// To prevent this, we adjust the rune count by removing the last
		// 3 runes, ensuring no partial characters are included.
		lineRunesSize -= 3
	}
	return lineRunes[:lineRunesSize], lineRunesSize
}

func indexOf(line, secret []rune, lineSize, secretSize int) int {
	for i := 0; i <= lineSize-secretSize; i++ {
		if compareRunes(line[i:i+secretSize], secret) {
			return i
		}
	}
	return -1
}

func compareRunes(a, b []rune) bool {
	// a and b must have the same size.
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
