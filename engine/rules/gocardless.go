package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var GocardlessAPITokenRegex = utils.GenerateSemiGenericRegex([]string{"gocardless"}, `live_(?i)[a-z0-9\-_=]{40}`, true)

func GoCardless() *Rule {
	return &Rule{
		BaseRuleID:  "abdf0043-764e-4903-b1a8-e03b7bd59e46",
		Description: "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.",
		RuleID:      "gocardless-api-token",
		Regex:       GocardlessAPITokenRegex,
		Keywords: []string{
			"live_",
			"gocardless",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
	}
}
