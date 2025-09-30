package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BeamerApiTokenRegex = utils.GenerateSemiGenericRegex([]string{"beamer"},
	`b_[a-z0-9=_\-]{44}`, true)

func BeamerApiToken() *NewRule {
	return &NewRule{
		Description: "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.",
		RuleID:      "beamer-api-token",
		Regex:       BeamerApiTokenRegex,
		Keywords:    []string{"beamer"},
	}
}
