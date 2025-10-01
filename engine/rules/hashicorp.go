package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var HashiCorpTerraformRegex = regexp.MustCompile(`(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`)

func HashiCorpTerraform() *NewRule {
	return &NewRule{
		BaseRuleID:  "bd82d203-3de7-4647-8986-0df7faad7374",
		Description: "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.",
		RuleID:      "hashicorp-tf-api-token",
		Regex:       HashiCorpTerraformRegex,
		Entropy:     3.5,
		Keywords:    []string{"atlasv1"},
		Severity:    "High",
	}
}
