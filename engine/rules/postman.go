package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var PostManAPIRegex = utils.GenerateUniqueTokenRegex(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`, false)

func PostManAPI() *NewRule {
	return &NewRule{
		BaseRuleID:  "bae405c3-705b-420b-bdc4-ed3613add3da",
		Description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
		RuleID:      "postman-api-token",
		Regex:       PostManAPIRegex,
		Entropy:     3,
		Keywords: []string{
			"PMAK-",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
