package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/checkmarx/2ms/v4/engine/rules"
)

// This script was used to generate remediations for rules based on their names
func main() {
	defaultRules := rules.GetDefaultRules(false)
	if len(defaultRules) == 0 {
		fmt.Println("No rules loaded — check your import path.")
		return
	}

	tagList := []string{
		"api-key", "client-id", "client-secret", "secret-key",
		"access-key", "access-id", "api-token", "access-token",
		"refresh-token", "private-key", "public-key", "encryption-key",
		"trigger-token", "registration-token", "password",
		"upload-token", "public-secret", "sensitive-url", "webhook",
	}

	var sb strings.Builder
	sb.WriteString("package sarif\n\n")
	sb.WriteString("var mapRuleRemediations = map[string]string{\n")

	for _, rule := range defaultRules {
		if rule == nil {
			continue
		}

		ruleName := rule.RuleName
		ruleID := rule.RuleID

		lastTwo := extractLastTwoWords(strings.ToLower(ruleName))
		matchedTag := findMatchingTag(lastTwo, tagList)

		var remediation string
		if matchedTag != "" {
			remediation = fmt.Sprintf("%s {secret}", matchedTag)
		} else {
			remediation = fmt.Sprintf("%s {secret}", ruleName)
		}

		sb.WriteString(fmt.Sprintf("\t%q: %q, // %s\n", ruleID, remediation, ruleName))
	}

	sb.WriteString("}\n")

	if err := os.WriteFile("rule_remediations.go", []byte(sb.String()), 0600); err != nil {
		panic(err)
	}

	fmt.Printf("✅ Generated rule_remediations.go with %d entries\n", len(defaultRules))
}

func extractLastTwoWords(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], "-")
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return ""
}

func findMatchingTag(name string, tags []string) string {
	for _, tag := range tags {
		if name == tag {
			return tag
		}
	}
	return ""
}
