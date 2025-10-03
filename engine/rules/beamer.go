package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BeamerApiTokenRegex = utils.GenerateSemiGenericRegex([]string{"beamer"},
	`b_[a-z0-9=_\-]{44}`, true)

func Beamer() *NewRule {
	return &NewRule{
		BaseRuleID:      "481dbb49-ccdc-4a83-97ad-e0961a004c8b",
		Description:     "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.",
		RuleID:          "beamer-api-token",
		Regex:           BeamerApiTokenRegex,
		Keywords:        []string{"beamer"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4},
	}
}
