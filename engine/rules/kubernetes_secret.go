package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

var kubernetesKindPat = `\bkind:[ \t]*["']?\bsecret\b["']?`

// Only matches values (`key: value`) under `data:` that are:
// - valid base64 characters
// - longer than 10 characters (no "YmFyCg==")
var kubernetesDataPat = `\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))` //nolint:lll

var KubernetesSecretRegex = regexp.MustCompile(fmt.Sprintf(
	`(?i)(?:%s(?s:.){0,200}?%s|%s(?s:.){0,200}?%s)`, kubernetesKindPat, kubernetesDataPat, kubernetesDataPat, kubernetesKindPat))

func KubernetesSecret() *Rule {
	return &Rule{
		BaseRuleID:  "7e7caacc-05fb-4e6e-b636-dbd027897a10",
		RuleID:      "kubernetes-secret-yaml",
		Description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
		Regex:       KubernetesSecretRegex,
		Keywords: []string{
			"secret",
		},
		// Kubernetes secrets are usually yaml files.
		Path: regexp.MustCompile(`(?i)\.ya?ml$`),
		AllowLists: []*AllowList{
			{
				Regexes: []*regexp.Regexp{
					// Ignore empty or placeholder values.
					// variable: {{ .Values.Example }} (https://helm.sh/docs/chart_template_guide/variables/)
					// variable: ""
					// variable: ''
					regexp.MustCompile(`[\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:\{\{[ \t\w"|$:=,.-]+}}|""|'')`),
				},
			},
			{
				// Avoid overreach between directives.
				RegexTarget: "match",
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(kind:(?s:.)+\n---\n(?s:.)+\bdata:|data:(?s:.)+\n---\n(?s:.)+\bkind:)`),
				},
			},
		},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
