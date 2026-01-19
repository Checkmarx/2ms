package ruledefine

import (
	"regexp"
)

var clojarsRegex = regexp.MustCompile(`(?i)CLOJARS_[a-z0-9]{60}`)

func Clojars() *Rule {
	return &Rule{
		RuleID:        "11012d42-0ea4-4543-bf87-b1674a5b7503",
		Description:   "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.", //nolint:lll
		RuleName:      "Clojars-Api-Token",
		Regex:         clojarsRegex.String(),
		Entropy:       2,
		Keywords:      []string{"clojars"}, // changed from clojars_ due to https://checkmarx.atlassian.net/browse/AST-96700
		Severity:      "High",
		Tags:          []string{TagApiToken},
		Category:      CategoryPackageManagement,
		ScoreRuleType: 4,
	}
}
