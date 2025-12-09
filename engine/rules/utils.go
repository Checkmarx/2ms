package rules

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// case insensitive prefix
	caseInsensitive = `(?i)`

	// identifier prefix (just an ignore group)
	identifierCaseInsensitivePrefix = `[\w.-]{0,50}?(?i:`
	identifierCaseInsensitiveSuffix = `)`
	identifierPrefix                = `[\w.-]{0,50}?(?:`
	identifierSuffix                = `)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}`
	identifierSuffixIncludingXml    = `)(?:[0-9a-z\-_\t .]{0,20})(?:<\/key>\s{0,10}<string)?(?:[\s|']|[\s|"]){0,3}`

	// commonly used assignment operators or function call
	// operator = `(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)`
	operator = `(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)`

	// boundaries for the secret
	// \x60 = `
	secretPrefixUnique       = `\b(`
	secretPrefix             = `[\x60'"\s=]{0,20}(`                                       //nolint:gosec // This is a regex pattern
	secretSuffix             = `)(?:[\x60'"\s;]|\\[nr]|$)`                                //nolint:gosec // This is a regex pattern
	secretSuffixIncludingXml = `)(?:['|\"|\n|\r|\s|\x60|;]|\\n|\\r|$|\s{0,10}<\/string>)` //nolint:gosec // This is a regex pattern
)

func generateSemiGenericRegex(identifiers []string, secretRegex string, isCaseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	// The identifiers should always be case-insensitive.
	// This is inelegant but prevents an extraneous `(?i:)` from being added to the pattern; it could be removed.
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
		writeIdentifiers(&sb, identifiers)
	} else {
		sb.WriteString(identifierCaseInsensitivePrefix)
		writeIdentifiers(&sb, identifiers)
		sb.WriteString(identifierCaseInsensitiveSuffix)
	}
	sb.WriteString(operator)
	sb.WriteString(secretPrefix)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return regexp.MustCompile(sb.String())
}

func writeIdentifiers(sb *strings.Builder, identifiers []string) {
	sb.WriteString(identifierPrefix)
	sb.WriteString(strings.Join(identifiers, "|"))
	sb.WriteString(identifierSuffix)
}

func generateUniqueTokenRegex(secretRegex string, isCaseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
	}
	sb.WriteString(secretPrefixUnique)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return regexp.MustCompile(sb.String())
}

func alphaNumeric(size string) string {
	return fmt.Sprintf(`[a-z0-9]{%s}`, size)
}

// generateSemiGenericRegexIncludingXml generates a regex that includes XML detection patterns
func generateSemiGenericRegexIncludingXml(identifiers []string, secretRegex string, isCaseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	// The identifiers should always be case-insensitive.
	// This is inelegant but prevents an extraneous `(?i:)` from being added to the pattern; it could be removed.
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
		writeIdentifiersIncludingXml(&sb, identifiers)
	} else {
		sb.WriteString(identifierCaseInsensitivePrefix)
		writeIdentifiersIncludingXml(&sb, identifiers)
		sb.WriteString(identifierCaseInsensitiveSuffix)
	}
	sb.WriteString(operator)
	sb.WriteString(secretPrefix)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffixIncludingXml)
	return regexp.MustCompile(sb.String())
}

func writeIdentifiersIncludingXml(sb *strings.Builder, identifiers []string) {
	sb.WriteString(identifierPrefix)
	sb.WriteString(strings.Join(identifiers, "|"))
	sb.WriteString(identifierSuffixIncludingXml)
}
