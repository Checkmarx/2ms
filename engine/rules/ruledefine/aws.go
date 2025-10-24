package ruledefine

import (
	"regexp"
)

var aWSRegex = regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`).String()

func AWS() *Rule {
	return &Rule{
		RuleID:      "3551707c-5e9a-4f7a-b433-8d824900f3c4",
		RuleName:    "aws-access-token",
		Description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.", //nolint:lll
		Regex:       aWSRegex,
		Entropy:     3,
		Keywords: []string{
			// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
			"A3T",  // todo: might not be a valid AWS token
			"AKIA", // Access key
			"ASIA", // Temporary (AWS STS) access key
			"ABIA", // AWS STS service bearer token
			"ACCA", // Context-specific credential
		},
		AllowLists: []*AllowList{
			{
				Regexes: []string{
					regexp.MustCompile(`.+EXAMPLE$`).String(),
				},
			},
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
