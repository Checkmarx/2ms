package ruledefine

var beamerApiTokenRegex = generateSemiGenericRegex([]string{"beamer"},
	`b_[a-z0-9=_\-]{44}`, true)

func Beamer() *Rule {
	return &Rule{
		RuleID: "481dbb49-ccdc-4a83-97ad-e0961a004c8b",
		Description: "Detected a Beamer API token," +
			" potentially compromising content management and exposing sensitive notifications and updates.",
		RuleName:        "beamer-api-token",
		Regex:           beamerApiTokenRegex.String(),
		Keywords:        []string{"beamer"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4},
	}
}
