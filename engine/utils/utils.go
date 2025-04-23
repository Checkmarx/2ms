package utils

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"github.com/checkmarx/2ms/engine/linecontent"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/zricethezav/gitleaks/v8/report"
	"io"
	"strings"
)

func BuildSecret(item plugins.ISourceItem, value report.Finding) (*secrets.Secret, error) {
	itemId := getFindingId(item, value)
	startLine := value.StartLine + 1
	endLine := value.EndLine + 1

	lineContent, err := linecontent.GetLineContent(value.Line, value.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get line content for source %s: %w", item.GetSource(), err)
	}

	secret := &secrets.Secret{
		ID:              itemId,
		Source:          item.GetSource(),
		RuleID:          value.RuleID,
		StartLine:       startLine,
		StartColumn:     value.StartColumn,
		EndLine:         endLine,
		EndColumn:       value.EndColumn,
		Value:           value.Secret,
		LineContent:     lineContent,
		RuleDescription: value.Description,
	}
	return secret, nil
}

func getFindingId(item plugins.ISourceItem, finding report.Finding) string {
	idParts := []string{item.GetID(), finding.RuleID, finding.Secret}
	sha := sha1.Sum([]byte(strings.Join(idParts, "-")))
	return fmt.Sprintf("%x", sha)
}

func IsSecretIgnored(secret *secrets.Secret, ignoredIds, allowedValues *[]string) bool {
	for _, allowedValue := range *allowedValues {
		if secret.Value == allowedValue {
			return true
		}
	}
	for _, ignoredId := range *ignoredIds {
		if secret.ID == ignoredId {
			return true
		}
	}
	return false
}

// ReadUntilSafeBoundary This hopefully avoids splitting. (https://github.com/gitleaks/gitleaks/issues/1651)
func ReadUntilSafeBoundary(r *bufio.Reader, n int, maxPeekSize int, peekBuf *bytes.Buffer) error {
	if peekBuf.Len() == 0 {
		return nil
	}

	// Does the buffer end in consecutive newlines?
	var (
		data         = peekBuf.Bytes()
		lastChar     = data[len(data)-1]
		newlineCount = 0 // Tracks consecutive newlines
	)
	if isWhitespace(lastChar) {
		for i := len(data) - 1; i >= 0; i-- {
			lastChar = data[i]
			if lastChar == '\n' {
				newlineCount++

				// Stop if two consecutive newlines are found
				if newlineCount >= 2 {
					return nil
				}
			} else if lastChar == '\r' || lastChar == ' ' || lastChar == '\t' {
				// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
				// (Intentionally do nothing.)
			} else {
				break
			}
		}
	}

	// If not, read ahead until we (hopefully) find some.
	newlineCount = 0
	for {
		data = peekBuf.Bytes()
		// Check if the last character is a newline.
		lastChar = data[len(data)-1]
		if lastChar == '\n' {
			newlineCount++

			// Stop if two consecutive newlines are found
			if newlineCount >= 2 {
				break
			}
		} else if lastChar == '\r' || lastChar == ' ' || lastChar == '\t' {
			// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
			// (Intentionally do nothing.)
		} else {
			newlineCount = 0 // Reset if a non-newline character is found
		}

		// Stop growing the buffer if it reaches maxSize
		if (peekBuf.Len() - n) >= maxPeekSize {
			break
		}

		// Read additional data into a temporary buffer
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		peekBuf.WriteByte(b)
	}
	return nil
}

func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}
