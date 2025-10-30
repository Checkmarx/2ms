package reporting

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/checkmarx/2ms/v4/lib/secrets"
)

const (
	scanTriggered  = " 2ms by Checkmarx scanning..."
	iconTask       = "▸"
	iconSuccess    = "✔"
	iconContext    = "→"
	defaultVersion = "0.0.0"
)

func writeHuman(report *Report, version string) (string, error) {
	var builder strings.Builder

	scanDuration := report.GetScanDuration()
	secretsBySource, uniqueRules := groupSecrets(report.GetResults())
	totalSecrets := report.TotalSecretsFound

	writeHeader(&builder, version)
	writeFindings(&builder, totalSecrets, secretsBySource)
	writeTotals(&builder, report.TotalItemsScanned, totalSecrets, len(secretsBySource), uniqueRules)
	writeFooter(&builder, scanDuration)

	return strings.TrimRight(builder.String(), "\n"), nil
}

func writeHeader(builder *strings.Builder, version string) {
	versionInfo := strings.TrimSpace(version)

	builder.WriteString(iconTask)
	builder.WriteString(scanTriggered)
	if versionInfo != "" && versionInfo != defaultVersion {
		builder.WriteString(" (version ")
		builder.WriteString(versionInfo)
		builder.WriteString(")")
	}
	builder.WriteString("\n\n")
}

func writeFindings(builder *strings.Builder, totalSecrets int, secretsBySource map[string][]*secrets.Secret) {
	builder.WriteString(iconContext)
	if totalSecrets == 0 {
		builder.WriteString(" Findings: none\n")
		return
	}

	fileCount := len(secretsBySource)
	builder.WriteString(fmt.Sprintf(
		" Findings: %d %s in %d %s\n",
		totalSecrets,
		pluralize(totalSecrets, "secret", "secrets"),
		fileCount,
		pluralize(fileCount, "file", "files"),
	))

	sources := sortedSources(secretsBySource)
	for _, source := range sources {
		displaySource := source
		if displaySource == "" {
			displaySource = "(source not provided)"
		}

		fmt.Fprintf(builder, "  - File: %s\n", displaySource)

		secrets := secretsBySource[source]
		sortSecrets(secrets)

		for idx, secret := range secrets {
			appendSecretDetails(builder, secret)
			if idx < len(secrets)-1 {
				builder.WriteString("\n")
			}
		}
		builder.WriteString("\n")
	}
}

func writeTotals(builder *strings.Builder, itemsScanned, totalSecrets, fileCount, ruleCount int) {
	builder.WriteString(iconContext)
	builder.WriteString(" Totals:\n")
	fmt.Fprintf(builder, "  - Items scanned: %d\n", itemsScanned)
	fmt.Fprintf(builder, "  - Secrets found: %d\n", totalSecrets)
	if totalSecrets > 0 {
		fmt.Fprintf(builder, "  - Files with secrets: %d\n", fileCount)
		fmt.Fprintf(builder, "  - Triggered rules: %d\n", ruleCount)
	}
}

func writeFooter(builder *strings.Builder, duration time.Duration) {
	builder.WriteString("\n")
	builder.WriteString(iconSuccess)
	fmt.Fprintf(builder, " Done in %s.", formatDuration(duration))
}

func groupSecrets(results map[string][]*secrets.Secret) (map[string][]*secrets.Secret, int) {
	secretsBySource := make(map[string][]*secrets.Secret)
	uniqueRules := make(map[string]struct{})

	for _, list := range results {
		for _, secret := range list {
			if secret == nil {
				continue
			}
			secretsBySource[secret.Source] = append(secretsBySource[secret.Source], secret)
			if secret.RuleID != "" {
				uniqueRules[secret.RuleID] = struct{}{}
			}
		}
	}

	return secretsBySource, len(uniqueRules)
}

func sortedSources(secretsBySource map[string][]*secrets.Secret) []string {
	sources := make([]string, 0, len(secretsBySource))
	for source := range secretsBySource {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return sources
}

func sortSecrets(secrets []*secrets.Secret) {
	sort.Slice(secrets, func(i, j int) bool {
		if secrets[i].StartLine != secrets[j].StartLine {
			return secrets[i].StartLine < secrets[j].StartLine
		}
		if secrets[i].StartColumn != secrets[j].StartColumn {
			return secrets[i].StartColumn < secrets[j].StartColumn
		}
		return secrets[i].RuleID < secrets[j].RuleID
	})
}

func appendSecretDetails(builder *strings.Builder, secret *secrets.Secret) {
	fmt.Fprintf(builder, "    - Rule: %s\n", fallback(secret.RuleID, "unknown"))
	fmt.Fprintf(builder, "      Secret ID: %s\n", fallback(secret.ID, "n/a"))
	fmt.Fprintf(builder, "      Location: %s\n", formatLocation(secret))

	if status := strings.TrimSpace(string(secret.ValidationStatus)); status != "" {
		fmt.Fprintf(builder, "      Validity: %s\n", status)
	}

	if secret.CvssScore > 0 {
		fmt.Fprintf(builder, "      CVSS score: %.1f\n", secret.CvssScore)
	}

	if snippet := trimmedSnippet(secret.LineContent); snippet != "" {
		fmt.Fprintf(builder, "      Snippet: %s\n", snippet)
	}

	if ruleDescription := strings.TrimSpace(secret.RuleDescription); ruleDescription != "" {
		fmt.Fprintf(builder, "      Description: %s\n", ruleDescription)
	}
}

func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}

func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
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
