package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

type ScoreParameters struct {
	Category RuleCategory
	RuleType uint8
}

type Rule struct {
	Rule            config.Rule
	Tags            []string
	ScoreParameters ScoreParameters
}

type NewRule struct {
	BaseRuleID      string //uuid4, should be consistent across changes in rule
	RuleID          string
	Description     string
	Type            string // the same as the existing category in ScoreParameters
	Regex           *regexp.Regexp
	Keywords        []string
	Entropy         float64
	Path            *regexp.Regexp  // present in some gitleaks secrets
	SecretGroup     int             // used to extract secret from regex match and used as the group that will have its entropy checked if `entropy` is set.
	ScoreParameters ScoreParameters //used for ASPM
	Severity        string
	OldSeverity     string //fallback for when the tenant has Critical FF turned OFF
	Deprecated      bool   //deprecated rules will remain in 2ms, with this as true
	AllowLists      []*AllowList
}

type AllowList struct { // For patterns that are allowed to be ignored
	Description    string
	MatchCondition string //determines whether all criteria must match. OR or AND
	Paths          []*regexp.Regexp
	RegexTarget    string //match or line. Default match
	Regexes        []*regexp.Regexp
	StopWords      []string // stop words that are allowed to be ignored
}
