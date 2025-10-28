package ruledefine

var mapboxAPITokenRegex = generateSemiGenericRegex(
	[]string{"mapbox"}, `pk\.[a-z0-9]{60}\.[a-z0-9]{22}`, true).String()

func MapBox() *Rule {
	return &Rule{
		RuleID:          "4e9bfc67-a523-4c9c-abc4-d9f20160aba2",
		Description:     "Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure.",
		RuleName:        "mapbox-api-token",
		Regex:           mapboxAPITokenRegex,
		Keywords:        []string{"mapbox"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryMappingAndLocationServices, RuleType: 4},
	}
}
