package ruledefine

import (
	"regexp"
)

var githubFineGrainedPATRegex = regexp.MustCompile(`github_pat_\w{82}`).String()

func GitHubFineGrainedPat() *Rule {
	return &Rule{
		RuleID:          "3f9b047a-f345-450d-b626-d25b3413175e",
		Description:     "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.",
		RuleName:        "Github-Fine-Grained-Pat",
		Regex:           githubFineGrainedPATRegex,
		Entropy:         3,
		Keywords:        []string{"github_pat_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
