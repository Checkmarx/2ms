package ruledefine

import (
	"fmt"

	"regexp"
)

var kubernetesKindPat = `\bkind:[ \t]*["']?\bsecret\b["']?`

// Only matches values (`key: value`) under `data:` that are:
// - valid base64 characters
// - longer than 10 characters (no "YmFyCg==")
var kubernetesDataPat = `\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))` //nolint:lll

var kubernetesSecretRegex = regexp.MustCompile(fmt.Sprintf(
	`(?i)(?:%s(?s:.){0,200}?%s|%s(?s:.){0,200}?%s)`, kubernetesKindPat, kubernetesDataPat, kubernetesDataPat, kubernetesKindPat)).String()

func KubernetesSecret() *Rule {
	return &Rule{
		RuleID:      "7e7caacc-05fb-4e6e-b636-dbd027897a10",
		RuleName:    "Kubernetes-Secret-Yaml",
		Description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
		Regex:       kubernetesSecretRegex,
		Keywords: []string{
			"secret",
		},
		// Kubernetes secrets are usually yaml files.
		Path: regexp.MustCompile(`(?i)\.ya?ml$`).String(),
		AllowLists: []*AllowList{
			{
				Regexes: []string{
					// Ignore empty or placeholder values.
					// variable: {{ .Values.Example }} (https://helm.sh/docs/chart_template_guide/variables/)
					// variable: ""
					// variable: ''
					regexp.MustCompile(`[\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:\{\{[ \t\w"|$:=,.-]+}}|""|'')`).String(),
				},
			},
			{
				// Avoid overreach between directives.
				RegexTarget: "match",
				Regexes: []string{
					regexp.MustCompile(`(kind:(?s:.)+\n---\n(?s:.)+\bdata:|data:(?s:.)+\n---\n(?s:.)+\bkind:)`).String(),
				},
			},
		},
		Severity:      "High",
		Tags:          []string{TagSecretKey},
		Category:      CategoryCloudPlatform,
		ScoreRuleType: 4,
	}
}
