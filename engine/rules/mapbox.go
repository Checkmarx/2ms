package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var MapboxAPITokenRegex = utils.GenerateSemiGenericRegex([]string{"mapbox"}, `pk\.[a-z0-9]{60}\.[a-z0-9]{22}`, true)

func MapBox() *Rule {
	return &Rule{
		BaseRuleID:      "4e9bfc67-a523-4c9c-abc4-d9f20160aba2",
		Description:     "Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure.",
		RuleID:          "mapbox-api-token",
		Regex:           MapboxAPITokenRegex,
		Keywords:        []string{"mapbox"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryMappingAndLocationServices, RuleType: 4},
	}
}
