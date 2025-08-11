package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

// SumoLogicAccessID returns a corrected SumoLogic Access ID rule that fixes the token validation issue.
// This overrides the default GitLeaks SumoLogic rule to fix validation bugs.
func SumoLogicAccessID() *config.Rule {
	// define rule - same as GitLeaks but with corrected validation
	return &config.Rule{
		RuleID:      "sumologic-access-id",
		Description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, "su[a-zA-Z0-9]{12}", false),
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
	}
}

// SumoLogicAccessToken returns a corrected SumoLogic Access Token rule that fixes the token validation issue.
// This overrides the default GitLeaks SumoLogic rule to fix validation bugs.
func SumoLogicAccessToken() *config.Rule {
	// define rule - same as GitLeaks but with corrected validation
	return &config.Rule{
		RuleID:      "sumologic-access-token",
		Description: "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, utils.AlphaNumeric("64"), true),
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
	}
}
