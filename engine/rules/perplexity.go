package rules

import (
	"regexp"
)

var PerplexityAPIKeyRegex = regexp.MustCompile(`\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`)

func PerplexityAPIKey() *NewRule {
	return &NewRule{
		BaseRuleID:      "c75f7c8d-e73a-4ef1-9eb9-84f3acddc253",
		Description:     "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.",
		RuleID:          "perplexity-api-key",
		Regex:           PerplexityAPIKeyRegex,
		Entropy:         4.0,
		Keywords:        []string{"pplx-"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
	}
}
