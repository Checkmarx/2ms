package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var HubspotAPIKeyRegex = utils.GenerateSemiGenericRegex([]string{"hubspot"},
	`[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`, true)

func HubSpot() *NewRule {
	return &NewRule{
		BaseRuleID:      "6c1eacb9-22a0-46d2-b372-f384d4feb860",
		Description:     "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
		RuleID:          "hubspot-api-key",
		Regex:           HubspotAPIKeyRegex,
		Keywords:        []string{"hubspot"},
		Severity:        "High",
		Tags:            []string{TagApiToken, TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryMarketingAutomation, RuleType: 4},
	}
}
