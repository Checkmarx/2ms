package rules

import (
	"regexp"
)

var SeverityOrder = []string{"Critical", "High", "Medium", "Low", "Info"}

type ScoreParameters struct {
	Category RuleCategory
	RuleType uint8
}

type Rule struct {
	BaseRuleID      string // uuid4, should be consistent across changes in rule
	RuleID          string
	Description     string
	Regex           *regexp.Regexp
	Keywords        []string
	Entropy         float64
	Path            *regexp.Regexp // present in some gitleaks secrets
	SecretGroup     int            // used to extract secret from regex match and used as the group that will have its entropy checked if `entropy` is set. //nolint:lll
	Severity        string
	OldSeverity     string // fallback for when critical is not enabled
	Deprecated      bool   // deprecated rules will remain in 2ms, with this as true
	AllowLists      []*AllowList
	Tags            []string
	ScoreParameters ScoreParameters // used for ASPM
}

type AllowList struct { // For patterns that are allowed to be ignored
	Description    string
	MatchCondition string // determines whether all criteria must match. OR or AND
	Paths          []*regexp.Regexp
	RegexTarget    string // match or line. Default match
	Regexes        []*regexp.Regexp
	StopWords      []string // stop words that are allowed to be ignored
}
