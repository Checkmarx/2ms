package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var RubyGemsAPITokenRegex = utils.GenerateUniqueTokenRegex(`rubygems_[a-f0-9]{48}`, false)

func RubyGemsAPIToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "33139118-434f-4e93-99fd-630243e94d93",
		Description: "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.",
		RuleID:      "rubygems-api-token",
		Regex:       RubyGemsAPITokenRegex,
		Entropy:     2,
		Keywords: []string{
			"rubygems_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
	}
}
