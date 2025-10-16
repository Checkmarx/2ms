package ruledefine

import (
	"regexp"
)

var hashiCorpTerraformRegex = regexp.MustCompile(`(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`)

func HashiCorpTerraform() *Rule {
	return &Rule{
		BaseRuleID: "bd82d203-3de7-4647-8986-0df7faad7374",
		Description: "Uncovered a HashiCorp Terraform user/org API token," +
			" which may lead to unauthorized infrastructure management and security breaches.",
		RuleID:          "hashicorp-tf-api-token",
		Regex:           hashiCorpTerraformRegex,
		Entropy:         3.5,
		Keywords:        []string{"atlasv1"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryInfrastructureAsCode, RuleType: 4},
	}
}
