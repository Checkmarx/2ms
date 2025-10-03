package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/base"
	gitleaksrule "github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
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
	secretPrefix             = `[\x60'"\s=]{0,5}(`                                        //nolint:gosec // This is a regex pattern
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

func createSingleRuleDetector(r *gitleaksrule.Rule) *detect.Detector {
	// normalize keywords like in the config package
	var (
		uniqueKeywords = make(map[string]struct{})
		keywords       []string
	)
	for _, keyword := range r.Keywords {
		k := strings.ToLower(keyword)
		if _, ok := uniqueKeywords[k]; ok {
			continue
		}
		keywords = append(keywords, k)
		uniqueKeywords[k] = struct{}{}
	}
	r.Keywords = keywords

	rules := map[string]gitleaksrule.Rule{
		r.RuleID: *r,
	}
	cfg := base.CreateGlobalConfig()
	cfg.Rules = rules
	cfg.Keywords = uniqueKeywords
	for _, a := range cfg.Allowlists {
		if err := a.Validate(); err != nil {
			logging.Fatal().Err(err).Msg("invalid global allowlist")
		}
	}
	return detect.NewDetector(cfg)
}

func ConvertNewRuleToGitleaksRule(rule *NewRule) *gitleaksrule.Rule {
	return &gitleaksrule.Rule{
		RuleID:      rule.RuleID,
		Description: rule.Description,
		Entropy:     rule.Entropy,
		SecretGroup: rule.SecretGroup,
		Regex:       rule.Regex,
		Path:        rule.Path,
		Keywords:    rule.Keywords,
		Allowlists:  convertAllowLists(rule.AllowLists),
	}
}

func convertAllowLists(allowLists []*AllowList) []*gitleaksrule.Allowlist {
	if len(allowLists) == 0 {
		return nil
	}
	out := make([]*gitleaksrule.Allowlist, 0, len(allowLists))
	for _, allowList := range allowLists {
		out = append(out, &gitleaksrule.Allowlist{
			Description:    allowList.Description,
			MatchCondition: toGitleaksMatchCondition(allowList.MatchCondition),
			Paths:          allowList.Paths,
			RegexTarget:    allowList.RegexTarget,
			Regexes:        allowList.Regexes,
			StopWords:      allowList.StopWords,
		})
	}
	return out
}

func toGitleaksMatchCondition(s string) gitleaksrule.AllowlistMatchCondition {
	switch strings.ToUpper(s) {
	case "AND":
		return gitleaksrule.AllowlistMatchAnd
	default:
		// default or fallback
		return gitleaksrule.AllowlistMatchOr
	}
}
