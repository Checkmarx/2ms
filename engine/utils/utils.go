package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"
	"github.com/checkmarx/2ms/engine/linecontent"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/h2non/filetype"
	"github.com/zricethezav/gitleaks/v8/report"
	"golang.org/x/sync/semaphore"
	"io"
	"strings"
)

const CxFileEndMarker = ";cx-file-end"

// BuildSecret creates a secret object from the given source item and finding
func BuildSecret(item plugins.ISourceItem, idx int, values []report.Finding, value report.Finding,
	pluginName string) (*secrets.Secret, error) {
	gitInfo := item.GetGitInfo()
	itemId := getFindingId(item, value)
	startLine, endLine, err := getStartAndEndLines(pluginName, gitInfo, value)
	if err != nil {
		return nil, fmt.Errorf("failed to get start and end lines for source %s: %w", item.GetSource(), err)
	}

	if idx == len(values)-1 && strings.HasSuffix(value.Line, CxFileEndMarker) {
		value.Line = value.Line[:len(value.Line)-len(CxFileEndMarker)]
		value.EndColumn--
	}

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

func getStartAndEndLines(pluginName string, gitInfo *plugins.GitInfo, value report.Finding) (int, int, error) {
	var startLine, endLine int
	var err error

	if pluginName == "filesystem" {
		startLine = value.StartLine + 1
		endLine = value.EndLine + 1
	} else if pluginName == "git" {
		startLine, endLine, err = plugins.GetGitStartAndEndLine(gitInfo, value.StartLine, value.EndLine)
		if err != nil {
			return 0, 0, err
		}
	} else {
		startLine = value.StartLine
		endLine = value.EndLine
	}

	return startLine, endLine, nil
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
			return fmt.Errorf("failed to read byte: %w", err)
		}
		peekBuf.WriteByte(b)
	}
	return nil
}

func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

// AcquireMemoryWeight acquires a semaphore with a specified weight
func AcquireMemoryWeight(ctx context.Context, weight, memoryBudget int64, sem *semaphore.Weighted) error {
	if weight > memoryBudget {
		return fmt.Errorf("buffer size %d exceeds memory budget %d", weight, memoryBudget)
	}
	if err := sem.Acquire(ctx, weight); err != nil {
		return fmt.Errorf("failed to acquire semaphore: %w", err)
	}
	return nil
}

// ShouldSkipFile checks if the file should be skipped based on its content type
func ShouldSkipFile(data []byte) bool {
	// TODO: could other optimizations be introduced here?
	mimetype, err := filetype.Match(data)
	if err != nil {
		return true // could not determine file type
	}
	return mimetype.MIME.Type == "application" // skip binary files
}
