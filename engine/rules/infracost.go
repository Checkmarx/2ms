package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var InfracostAPITokenRegex = utils.GenerateUniqueTokenRegex(`ico-[a-zA-Z0-9]{32}`, false)

func InfracostAPIToken() *Rule {
	return &Rule{
		BaseRuleID:      "0774bdec-232f-4c68-8ba0-458f5e1e40c8",
		Description:     "Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data.",
		RuleID:          "infracost-api-token",
		Regex:           InfracostAPITokenRegex,
		Entropy:         3,
		Keywords:        []string{"ico-"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
	}
}
