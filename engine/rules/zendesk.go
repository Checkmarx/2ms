package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var ZendeskSecretKeyRegex = utils.GenerateSemiGenericRegex([]string{"zendesk"}, utils.AlphaNumeric("40"), true)

func ZendeskSecretKey() *Rule {
	return &Rule{
		BaseRuleID:  "ef6ad1b6-cb89-44a9-9e70-783095456d62",
		Description: "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.",
		RuleID:      "zendesk-secret-key",
		Regex:       ZendeskSecretKeyRegex,
		Keywords: []string{
			"zendesk",
		},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryCustomerSupport, RuleType: 4},
	}
}
