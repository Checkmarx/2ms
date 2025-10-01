package rules

import (
	"regexp"
)

var GithubFineGrainedPATRegex = regexp.MustCompile(`github_pat_\w{82}`)

func GithubFineGrainedPat() *NewRule {
	return &NewRule{
		BaseRuleID:  "3f9b047a-f345-450d-b626-d25b3413175e",
		Description: "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.",
		RuleID:      "github-fine-grained-pat",
		Regex:       GithubFineGrainedPATRegex,
		Entropy:     3,
		Keywords:    []string{"github_pat_"},
		Severity:    "High",
	}
}
