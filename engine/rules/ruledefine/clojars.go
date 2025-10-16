package ruledefine

import (
	"regexp"
)

var clojarsRegex = regexp.MustCompile(`(?i)CLOJARS_[a-z0-9]{60}`)

func Clojars() *Rule {
	return &Rule{
		BaseRuleID:      "11012d42-0ea4-4543-bf87-b1674a5b7503",
		Description:     "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.", //nolint:lll
		RuleID:          "clojars-api-token",
		Regex:           clojarsRegex,
		Entropy:         2,
		Keywords:        []string{"clojars"}, // changed from clojars_ due to https://checkmarx.atlassian.net/browse/AST-96700
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
	}
}
