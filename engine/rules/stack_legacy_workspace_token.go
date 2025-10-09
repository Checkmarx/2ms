package rules

import (
	"regexp"
)

var SlackLegacyWorkspaceTokenRegex = regexp.MustCompile(`xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}`)

func SlackLegacyWorkspaceToken() *Rule {
	return &Rule{
		BaseRuleID:  "1a525661-ac3b-415b-b9d6-ec147b2dd49c",
		RuleID:      "slack-legacy-workspace-token",
		Description: "Identified a Slack Legacy Workspace token, potentially compromising access to workspace data and legacy features.",
		// This is by far the least confident pattern.
		Regex:   SlackLegacyWorkspaceTokenRegex,
		Entropy: 2,
		Keywords: []string{
			"xoxa",
			"xoxr",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
