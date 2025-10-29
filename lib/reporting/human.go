package reporting

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/checkmarx/2ms/v4/lib/secrets"
)

const (
	colorPrimary    = "\033[36m"
	colorSecondary  = "\033[35m"
	colorHighlight  = "\033[33m"
	colorFileLabel  = "\033[32m"
	colorReset      = "\033[0m"
	statusCompleted = "2ms scanning..."
)

func writeHuman(report *Report) (string, error) {
	var builder strings.Builder

	builder.WriteString(colorPrimary)
	builder.WriteString(statusCompleted)
	builder.WriteString(colorReset + "\n\n")

	totalSecrets := report.TotalSecretsFound
	results := report.GetResults()

	secretsBySource := make(map[string][]*secrets.Secret)
	uniqueRules := make(map[string]struct{})

	for _, list := range results {
		for _, secret := range list {
			if secret == nil {
				continue
			}
			source := secret.Source
			secretsBySource[source] = append(secretsBySource[source], secret)
			if secret.RuleID != "" {
				uniqueRules[secret.RuleID] = struct{}{}
			}
		}
	}

	if totalSecrets == 0 {
		builder.WriteString("No secrets were detected during this scan.\n\n")
	} else {
		sources := make([]string, 0, len(secretsBySource))
		for source := range secretsBySource {
			sources = append(sources, source)
		}
		sort.Strings(sources)

		for _, source := range sources {
			displaySource := source
			if displaySource == "" {
				displaySource = "(source not provided)"
			}

			fmt.Fprintf(&builder, "%sFile:%s %s%s%s\n", colorFileLabel, colorReset, colorHighlight, displaySource, colorReset)

			secretsSlice := secretsBySource[source]
			sort.Slice(secretsSlice, func(i, j int) bool {
				if secretsSlice[i].StartLine != secretsSlice[j].StartLine {
					return secretsSlice[i].StartLine < secretsSlice[j].StartLine
				}
				if secretsSlice[i].StartColumn != secretsSlice[j].StartColumn {
					return secretsSlice[i].StartColumn < secretsSlice[j].StartColumn
				}
				return secretsSlice[i].RuleID < secretsSlice[j].RuleID
			})

			for idx, secret := range secretsSlice {
				appendSecretDetails(&builder, secret)
				if idx < len(secretsSlice)-1 {
					builder.WriteString("\n")
				}
			}

			builder.WriteString("\n")
		}
	}

	builder.WriteString(colorSecondary + "Totals" + colorReset + "\n")
	builder.WriteString(colorSecondary + "------" + colorReset + "\n")
	fmt.Fprintf(&builder, "%sItems scanned:%s %d\n", colorSecondary, colorReset, report.TotalItemsScanned)
	fmt.Fprintf(&builder, "%sSecrets found:%s %d\n", colorSecondary, colorReset, totalSecrets)
	if totalSecrets > 0 {
		fmt.Fprintf(&builder, "%sFiles with secrets:%s %d\n", colorSecondary, colorReset, len(secretsBySource))
		fmt.Fprintf(&builder, "%sTriggered rules:%s %d\n", colorSecondary, colorReset, len(uniqueRules))
	}
	fmt.Fprintf(&builder, "%sScan duration:%s %s\n", colorSecondary, colorReset, formatDuration(report.GetScanDuration()))

	return strings.TrimRight(builder.String(), "\n"), nil
}

func appendSecretDetails(builder *strings.Builder, secret *secrets.Secret) {
	fmt.Fprintf(builder, "  - %sRule:%s %s\n", colorSecondary, colorReset, fallback(secret.RuleID, "unknown"))
	fmt.Fprintf(builder, "    %sSecret ID:%s %s\n", colorSecondary, colorReset, fallback(secret.ID, "n/a"))
	fmt.Fprintf(builder, "    %sLocation:%s %s\n", colorSecondary, colorReset, formatLocation(secret))

	if status := strings.TrimSpace(string(secret.ValidationStatus)); status != "" {
		fmt.Fprintf(builder, "    %sValidation:%s %s\n", colorSecondary, colorReset, status)
	}

	if secret.CvssScore > 0 {
		fmt.Fprintf(builder, "    %sCVSS score:%s %.1f\n", colorSecondary, colorReset, secret.CvssScore)
	}

	if snippet := trimmedSnippet(secret.LineContent); snippet != "" {
		fmt.Fprintf(builder, "    %sSnippet:%s %s\n", colorSecondary, colorReset, snippet)
	}

	if remediation := strings.TrimSpace(secret.RuleDescription); remediation != "" {
		fmt.Fprintf(builder, "    %sRemediation:%s %s\n", colorSecondary, colorReset, remediation)
	}
}

func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}

func formatLocation(secret *secrets.Secret) string {
	var parts []string

	switch {
	case secret.StartLine > 0 && secret.EndLine > 0:
		if secret.StartLine == secret.EndLine {
			parts = append(parts, fmt.Sprintf("line %d", secret.StartLine))
		} else {
			parts = append(parts, fmt.Sprintf("lines %d-%d", secret.StartLine, secret.EndLine))
		}
	case secret.StartLine > 0:
		parts = append(parts, fmt.Sprintf("line %d", secret.StartLine))
	case secret.EndLine > 0:
		parts = append(parts, fmt.Sprintf("line %d", secret.EndLine))
	}

	if column := formatColumnRange(secret.StartColumn, secret.EndColumn); column != "" {
		parts = append(parts, column)
	}

	if len(parts) == 0 {
		return "n/a"
	}

	return strings.Join(parts, ", ")
}

func formatColumnRange(start, end int) string {
	switch {
	case start > 0 && end > 0 && start != end:
		return fmt.Sprintf("columns %d-%d", start, end)
	case start > 0:
		return fmt.Sprintf("column %d", start)
	case end > 0:
		return fmt.Sprintf("column %d", end)
	default:
		return ""
	}
}

func trimmedSnippet(snippet string) string {
	snippet = strings.TrimSpace(snippet)
	const maxLen = 160
	if len(snippet) > maxLen {
		return snippet[:maxLen-3] + "..."
	}
	return snippet
}

func formatDuration(duration time.Duration) string {
	if duration <= 0 {
		return "0s"
	}

	if duration < time.Second {
		return duration.Round(time.Millisecond).String()
	}

	return duration.Round(10 * time.Millisecond).String()
}
