package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var ClojarsRegex = regexp.MustCompile(`(?i)CLOJARS_[a-z0-9]{60}`)

func Clojars() *NewRule {
	return &NewRule{
		BaseRuleID:      "11012d42-0ea4-4543-bf87-b1674a5b7503",
		Description:     "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.",
		RuleID:          "clojars-api-token",
		Regex:           ClojarsRegex,
		Entropy:         2,
		Keywords:        []string{"clojars"}, //changed from clojars_ due to https://checkmarx.atlassian.net/browse/AST-96700
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
	}
}
