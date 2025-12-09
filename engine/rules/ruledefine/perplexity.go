package ruledefine

import (
	"regexp"
)

var perplexityAPIKeyRegex = regexp.MustCompile(`\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`).String()

func PerplexityAPIKey() *Rule {
	return &Rule{
		RuleID:        "c75f7c8d-e73a-4ef1-9eb9-84f3acddc253",
		Description:   "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.",
		RuleName:      "Perplexity-Api-Key",
		Regex:         perplexityAPIKeyRegex,
		Entropy:       4.0,
		Keywords:      []string{"pplx-"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategoryAIAndMachineLearning,
		ScoreRuleType: 4,
	}
}
