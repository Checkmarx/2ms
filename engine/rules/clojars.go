package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func Clojars() *config.Rule {
	return &config.Rule{
		Description: "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.",
		RuleID:      "clojars-api-token",
		Regex:       regexp.MustCompile(`(?i)CLOJARS_[a-z0-9]{60}`),
		Keywords:    []string{"clojars"},
	}
}
