package ruledefine

import (
	"fmt"

	"regexp"
)

var hashicorpKeywords = []string{"administrator_login_password", "password"}
var hashicorpTfPasswordRegex = generateSemiGenericRegex(
	hashicorpKeywords, fmt.Sprintf(`"%s"`, AlphaNumericExtended("8,20")), true) //nolint:gocritic

func HashicorpField() *Rule {
	return &Rule{
		BaseRuleID: "8477ac09-107c-48a9-a51b-62052600a3f0",
		Description: "Identified a HashiCorp Terraform password field," +
			" risking unauthorized infrastructure configuration and security breaches.",
		RuleID:          "hashicorp-tf-password",
		Regex:           hashicorpTfPasswordRegex,
		Entropy:         2,
		Keywords:        hashicorpKeywords,
		Path:            regexp.MustCompile(`(?i)\.(?:tf|hcl)$`),
		Severity:        "High",
		Tags:            []string{TagPassword},
		ScoreParameters: ScoreParameters{Category: CategoryInfrastructureAsCode, RuleType: 4},
	}
}
