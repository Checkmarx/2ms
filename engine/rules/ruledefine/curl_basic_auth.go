package ruledefine

import (
	"regexp"
)

var CurlBasicAuthRegex = regexp.MustCompile(
	`\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\w${}@.-]+)))(?:\s|\z)`) //nolint:lll

func CurlBasicAuth() *Rule {
	return &Rule{
		BaseRuleID:  "a80aed71-d4ac-499a-a154-befb592e461b",
		RuleID:      "curl-auth-user",
		Description: "Discovered a potential basic authorization token provided in a curl command, which could compromise the curl accessed resource.", //nolint:lll
		Regex:       CurlBasicAuthRegex,
		Keywords:    []string{"curl"},
		Entropy:     2,
		AllowLists: []*AllowList{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\*+|x+)`), // common placeholder passwords
					regexp.MustCompile(`['"]?<[^>]+>['"]?:['"]?<[^>]+>|<[^:]+:[^>]+>['"]?`),             // <placeholder>
					regexp.MustCompile(`[^:]+:\[[^]]+]`),                                                // [placeholder]
					regexp.MustCompile(`['"]?[^:]+['"]?:['"]?\$(?:\d|\w+|\{(?:\d|\w+)})['"]?`),          // $1 or $VARIABLE
					regexp.MustCompile(`\$\([^)]+\):\$\([^)]+\)`),                                       // $(cat login.txt)
					regexp.MustCompile(`['"]?\$?{{[^}]+}}['"]?:['"]?\$?{{[^}]+}}['"]?`),                 // ${{ secrets.FOO }} or {{ .Values.foo }}
				},
			},
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryNetworking, RuleType: 4},
	}
}
